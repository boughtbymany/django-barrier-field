from django import forms
from django.contrib import admin

from barrier_field.client import cognito_client
from barrier_field.models import User
from barrier_field.utils import get_user_data_model, verify_user_email
from barrier_field.reverse_admin import ReverseModelAdmin
from django.contrib.auth.password_validation import validate_password


class AdditionalUserFields(forms.ModelForm):
    email_address_verified = forms.BooleanField(required=False)
    cognito = cognito_client()

    def clean_password(self):
        password = self.cleaned_data.get('password')
        validate_password(password)
        return password

    def get_initial_for_field(self, field, field_name):
        if self.instance and self.instance.pk:
            self.cognito.username = self.instance.email
            user = self.cognito.admin_get_user()
            if field_name == 'email_address_verified':
                return user.email_verified

        return super().get_initial_for_field(field, field_name)

    def save(self, commit=True):
        self.cognito.username = self.instance.email
        email_address_verified = self.cleaned_data.pop(
            'email_address_verified', False
        )

        user = super(AdditionalUserFields, self).save(commit=commit)
        if not self.instance.pk:
            user.register_on_cognito()
        verify_user_email(self.cognito, set=email_address_verified)
        return super(AdditionalUserFields, self).save(commit=commit)

    class Meta:
        model = User
        fields = '__all__'


user_data_model = get_user_data_model()
if user_data_model:
    class UserAdmin(ReverseModelAdmin):
        form = AdditionalUserFields
        inline_type = 'tabular'
        inline_reverse = ['user_data', ]
    admin.site.register(User, UserAdmin)
else:
    admin.site.register(User)
