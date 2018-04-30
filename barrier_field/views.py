from uuid import uuid4
import qrcode

from django.contrib.auth.decorators import login_required
from django.core.files import File
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.views.generic import FormView, TemplateView
from warrant.exceptions import ForceChangePasswordException

from barrier_field import forms
from barrier_field.backend import register, complete_login
from barrier_field.client import cognito
from barrier_field.exceptions import MFARequiredSMS, MFARequiredSoftware


def login_view(request):
    try:
        return LoginView.as_view()(request)
    except ForceChangePasswordException:
        # New user must change their temporary password
        request.session['login_data'] = request.POST
        return redirect(reverse('force-change-password'))
    except MFARequiredSMS:
        return redirect(reverse('sms-mfa'))
    except MFARequiredSoftware:
        return redirect(reverse('software-mfa'))


def logout_view(request):
    user = get_user_model().objects.get(username=request.user.username)
    logout(request)
    if getattr(settings, 'CLEAR_USER_ON_LOGOUT', True):
        user.delete()
    return LogoutView.as_view()(request)


class Register(FormView):
    template_name = 'register.html'
    form_class = forms.UserCreateForm
    success_url = '/'

    def form_valid(self, form):
        User = get_user_model()
        create_user = {
            'username': form.cleaned_data['username'],
            'password': form.cleaned_data['password1'],
            'is_superuser': form.cleaned_data['is_superuser'],
            'is_staff': form.cleaned_data['is_staff']
        }

        # Register with cognito
        register(self.request, create_user)
        User.objects.create_user(**create_user)
        new_user = authenticate(
            username=create_user['username'],
            password=create_user['password']
        )
        login(self.request, new_user)
        return super(Register, self).form_valid(form)


class Update(FormView):
    template_name = 'register.html'
    form_class = forms.UserUpdateform
    success_url = '/'

    def form_valid(self, form):
        User_model = get_user_model()
        user = User_model.objects.get(username=form.cleaned_data['username'])
        update_user = {
            'is_superuser': form.cleaned_data['is_superuser'],
            'is_staff': form.cleaned_data['is_staff']
        }
        user.objects.update_user(**update_user)
        user.save(update_cognito=True)
        return super(Update, self).form_valid(form)


class ForceChangePassword(FormView):
    form_class = forms.PasswordUpdateForm
    template_name = 'update_cognito_password.html'

    def form_valid(self, form):
        login_form_data = self.request.session.get('login_data')
        current_password = login_form_data.get('password')
        new_password = form.cleaned_data['password1']
        try:
            cognito.new_password_challenge(current_password, new_password)
        except Exception as e:
            try:
                error = e.response['Error']
            except AttributeError:
                raise AttributeError('Something went wrong there...')
            if error['Code'] == 'InvalidPasswordException':
                form.add_error(field='password1', error=error['Message'])
                return super(ForceChangePassword, self).form_invalid(form)
        else:
            # Remove login data from session
            self.request.session.pop('login_data')
            user = authenticate(
                username=cognito.username, password=new_password
            )
            login(self.request, user)
            return redirect('/')


class SMSMFA(FormView):
    form_class = forms.MFACode
    template_name = 'authenticate_mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SMSMFA, self).get_context_data(**kwargs)
        context['mfa_type'] = 'SMS'
        return context

    def form_valid(self, form):
        code = form.cleaned_data['mfa_code']
        response = cognito.respond_to_auth_challenge(
            'SMS_MFA', code, cognito.username,
            self.request.session.pop('MFA_CHALLENGE').get('Session')
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            complete_login(self.request, response)
        return redirect(getattr(settings, 'LOGIN_REDIRECT_URL', '/'))


class SoftwareMFA(FormView):
    form_class = forms.MFACode
    template_name = 'authenticate_mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SoftwareMFA, self).get_context_data(**kwargs)
        context['mfa_type'] = 'Software'
        return context

    def form_valid(self, form):
        code = form.cleaned_data['mfa_code']
        response = cognito.respond_to_auth_challenge(
            'SOFTWARE_TOKEN_MFA', code, cognito.username,
            self.request.session.pop('MFA_CHALLENGE').get('Session')
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            complete_login(self.request, response)
        return redirect(getattr(settings, 'LOGIN_REDIRECT_URL', '/'))


class SetSoftwareMFA(FormView):
    form_class = forms.MFACode
    template_name = 'associate-software-mfa.html'

    def get_context_data(self, **kwargs):
        context = super(SetSoftwareMFA, self).get_context_data(**kwargs)
        response = cognito.associate_software_token(self.request)
        secret_code = response['SecretCode']
        OTP = f'otpauth://totp/Username:{self.request.user.username}?secret={secret_code}&issuer=BoughtByMany'
        qr_code = qrcode.make(OTP)
        save_location = f'static/temp/code-{uuid4()}.png'
        qr_code.save(save_location)
        context['qr_code'] = save_location.replace('static/', '')
        context['token_code'] = secret_code
        context['mfa_type'] = 'SOFTWARE'
        return context

    def form_valid(self, form):
        code = form.cleaned_data['mfa_code']
        response = cognito.verify_software_token(self.request, code)
        if response['Status'] == 'SUCCESS':
            cognito.update_software_mfa(self.request, enabled=True)
        return redirect('/')


class MFASettings(FormView):
    form_class = forms.MFASettings
    template_name = 'mfa-settings.html'
    sms_enabled = None
    software_enabled = None

    def get_initial(self):
        user = cognito.get_user_detailed()
        mfa_preferences = user.get('UserMFASettingList')

        initial = super(MFASettings, self).get_initial()
        if not mfa_preferences:
            return initial

        if 'SOFTWARE_TOKEN_MFA' in mfa_preferences:
            self.software_enabled = True
            initial['software_mfa'] = True
        if 'SMS_MFA' in mfa_preferences:
            self.sms_enabled = True
            initial['sms_mfa'] = True

        return initial

    def form_valid(self, form):
        sms = (
            form.cleaned_data['sms_mfa'],
            self.sms_enabled
        )
        if sms[0] and not sms[1]:
            cognito.update_sms_mfa(self.request, enabled=True)
        if sms[1] and not sms[0]:
            cognito.update_sms_mfa(self.request, enabled=False)

        software = (
            form.cleaned_data['software_mfa'],
            self.software_enabled
        )
        if software[0] and not software[1]:
            return redirect(reverse('associate-mfa'))
        if software[1] and not software[0]:
            cognito.update_software_mfa(self.request, enabled=False)

        return redirect(reverse('mfa-settings'))
