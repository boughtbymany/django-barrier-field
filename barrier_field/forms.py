from django import forms
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
                self.user_cache = authenticate(self.request, username=username, password=password)
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


class PasswordChangeForm(forms.Form):
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

    new_password1 = forms.CharField(
        required=True,
        label='New password',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'new_password1',
                'placeholder': 'New password',
                'class': 'form__text'
            }
        )
    )

    new_password2 = forms.CharField(
        required=True,
        label='Confirm new password',
        widget=forms.PasswordInput(
            render_value=False,
            attrs={
                'name': 'new_password2',
                'placeholder': 'Confirm new password',
                'class': 'form__text'
            }
        ),
        help_text=('Enter the same password as above, for verification.')
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')

        if (password1 and password2) and password1 != password2:
            raise forms.ValidationError(
                "The two password fields didn't match."
            )

        return password2


class UserCreateForm(UserCreationForm):
    is_superuser = forms.BooleanField(required=False)
    is_staff = forms.BooleanField(required=False)


class UserUpdateform(UserChangeForm):
    is_superuser = forms.BooleanField(required=False)
    is_staff = forms.BooleanField(required=False)


class MFACode(forms.Form):
    mfa_code = forms.CharField(
        required=True,
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
