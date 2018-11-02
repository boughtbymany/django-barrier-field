from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, \
    AuthenticationForm

from barrier_field.exceptions import catch_login_exceptions


class LoginForm(AuthenticationForm):
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username is not None and password:
            try:
                self.user_cache = authenticate(
                    self.request, username=username, password=password
                )
            except catch_login_exceptions:
                # Carry on and catch exception in view
                return self.cleaned_data

            if self.user_cache is None:
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                    params={'username': self.username_field.verbose_name},
                )
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data


class PasswordUpdateForm(forms.Form):
    password1 = forms.CharField(
        required=True,
        label='Password',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'password1',
                'placeholder': 'New password',
                'class': 'form__text'
            }
        )
    )

    password2 = forms.CharField(
        required=True,
        label='Confirm password',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'password2',
                'placeholder': 'Confirm new password',
                'class': 'form__text'
            }
        ),
        help_text=('Enter the same password as above, for verification.')
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if (password1 and password2) and password1 != password2:
            raise forms.ValidationError(
                "The two password fields didn't match."
            )

        return password2


class PasswordChangeForm(PasswordUpdateForm):

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super(PasswordChangeForm, self).__init__(*args, **kwargs)

    field_order = ['current_password', 'password1', 'password2']

    current_password = forms.CharField(
        required=True,
        label='Current password',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'current_password',
                'placeholder': 'Current password',
                'class': 'form__text'
            }
        )
    )

    def clean_current_password(self):
        """
        Validates that the old_password field is correct.
        """
        old_password = self.cleaned_data["current_password"]
        if not self.user.check_password(old_password):
            raise forms.ValidationError(
                "current password is wrong"
            )
        return old_password


class UserCreationForm(forms.ModelForm):

    error_messages = {
        'duplicate_email': _("A user with that email already exists."),
        'password_mismatch': _("The two password fields didn't match."),
    }

    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput)
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."))

    class Meta:  # noqa: D101
        model = get_user_model()
        fields = ('email', )

    def clean_email(self):
        email = self.cleaned_data["email"]
        try:
            get_user_model()._default_manager.get(email=email)
        except get_user_model().DoesNotExist:
            return email
        raise forms.ValidationError(
            self.error_messages['duplicate_email'],
            code='duplicate_email',
        )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserUpdateform(UserChangeForm):
    is_superuser = forms.BooleanField(required=False)
    is_staff = forms.BooleanField(required=False)


class MFACode(forms.Form):
    mfa_code = forms.CharField(
        required=True,
        min_length=6,
        label='One Time Password',
        widget=forms.TextInput(
            attrs={
                'name': 'mfa_code',
                'placeholder': 'One time password',
                'class': 'form__text'
            }
        )
    )


class MFASettings(forms.Form):
    software_mfa = forms.BooleanField(required=False)
    sms_mfa = forms.BooleanField(required=False)


class ForgotPassword(forms.Form):
    email_address = forms.CharField(max_length=255, required=True)

    def clean_email_address(self):
        email_address = self.cleaned_data.get("email_address")

        try:
            get_user_model().objects.get(email=email_address)
        except get_user_model().DoesNotExist:
            raise forms.ValidationError(
                'Invalid Email '
            )
        return email_address


class ForgotPasswordConfirm(PasswordUpdateForm):
    field_order = [
        'email_address', 'verification_code', 'password1', 'password2'
    ]
    email_address = forms.CharField(
        required=True,
        label='Email Address',
        widget=forms.TextInput(
            attrs={
                'name': 'email_address',
                'placeholder': 'Email Address',
                'class': 'form__text'
            }
        )
    )

    verification_code = forms.CharField(
        required=True,
        label='Verification code',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'verification_code',
                'placeholder': 'Verification Code',
                'class': 'form__text'
            }
        )
    )

    def clean_email_address(self):
        email_address = self.cleaned_data.get("email_address")

        try:
            get_user_model().objects.get(email=email_address)
        except get_user_model().DoesNotExist:
            raise forms.ValidationError(
                'Invalid Email '
            )
        return email_address
