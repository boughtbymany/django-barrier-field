from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm


class PasswordUpdateForm(forms.Form):
    password1 = forms.CharField(
        required=True,
        label='Password',
        widget=forms.PasswordInput(render_value=False)
    )

    password2 = forms.CharField(
        required=True,
        label='Confirm password',
        widget=forms.PasswordInput(render_value=False),
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


class UserCreateForm(UserCreationForm):
    is_superuser = forms.BooleanField(required=False)
    is_staff = forms.BooleanField(required=False)


class UserUpdateform(UserChangeForm):
    is_superuser = forms.BooleanField(required=False)
    is_staff = forms.BooleanField(required=False)


class MFACode(forms.Form):
    mfa_code = forms.CharField(required=True, label='One Time Password')


class MFASettings(forms.Form):
    software_mfa = forms.BooleanField(required=False)
    sms_mfa = forms.BooleanField(required=False)
