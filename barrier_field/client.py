from django.conf import settings
from types import MethodType
from warrant import Cognito, AWSSRP

from barrier_field.exceptions import MFARequiredSMS, MFARequiredSoftware, \
    MFAMismatch

cognito = Cognito(
    settings.COGNITO_USER_POOL_ID,
    settings.COGNITO_APP_ID,
    access_key=getattr(settings, 'AWS_ACCESS_KEY_ID', None),
    secret_key=getattr(settings, 'AWS_SECRET_ACCESS_KEY', None)
)


def auth_error_handler(self, exception):
    """
    Handle generic botocore 'errorfactory' errors
    """
    if not getattr(exception, 'response', False):
        raise exception
    error = exception.response.get('Error')
    if error:
        if error['Code'] == 'NotAuthorizedException':
            # Handle disabled user
            if error['Message'] == 'User is disabled':
                self.sync_cache(
                    {'username': cognito.username}, deactivate=True
                )
                return None
            if error['Message'] == 'Incorrect username or password.':
                return None
        if error['Code'] == 'UserNotFoundException':
            return None
        if error['Code'] == 'CodeMismatchException':
            raise MFAMismatch()
        raise exception
    else:
        raise exception


def register_method(method):
    setattr(cognito, f'{method.__name__}', MethodType(method, cognito))


def authenticate(self, password, request):
    """
    Authenticate the user using the SRP protocol

    OVERRIDE: Updated authenticate method to handle password challenges,
    required for MFA auth
    :param password: The user's passsword
    :return:
    """
    aws = AWSSRP(username=self.username, password=password,
                 pool_id=self.user_pool_id,
                 client_id=self.client_id, client=self.client,
                 client_secret=self.client_secret)
    tokens = aws.authenticate_user()
    if tokens.get('ChallengeName'):
        challenge_type = tokens['ChallengeName']
        request.session['MFA_CHALLENGE'] = tokens
        if challenge_type == 'SMS_MFA':
            raise MFARequiredSMS()
        if challenge_type == 'SOFTWARE_TOKEN_MFA':
            raise MFARequiredSoftware()
    self.verify_token(tokens['AuthenticationResult']['IdToken'], 'id_token',
                      'id')
    self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
    self.verify_token(tokens['AuthenticationResult']['AccessToken'],
                      'access_token', 'access')
    self.token_type = tokens['AuthenticationResult']['TokenType']


def admin_disable_user(self):
    self.client.admin_disable_user(
        UserPoolId=self.user_pool_id,
        Username=self.username
    )


def admin_enable_user(self):
    self.client.admin_enable_user(
        UserPoolId=self.user_pool_id,
        Username=self.username
    )


def respond_to_auth_challenge(self, challenge_type, challenge_response,
                              username, session):
    if challenge_type == 'SMS_MFA':
        response_code = 'SMS_MFA_CODE'
    else:
        response_code = 'SOFTWARE_TOKEN_MFA_CODE'
    tokens = self.client.admin_respond_to_auth_challenge(
        UserPoolId=self.user_pool_id,
        ClientId=self.client_id,
        Session=session,
        ChallengeName=challenge_type,
        ChallengeResponses={
            response_code: challenge_response,
            'USERNAME': username
        }
    )
    self.verify_token(tokens['AuthenticationResult']['IdToken'], 'id_token',
                      'id')
    self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
    self.verify_token(tokens['AuthenticationResult']['AccessToken'],
                      'access_token', 'access')
    self.token_type = tokens['AuthenticationResult']['TokenType']
    return tokens


def associate_software_token(self, request):
    response = self.client.associate_software_token(
        AccessToken=self.access_token
    )
    return response


def verify_software_token(self, request, mfa_code):
    response = self.client.verify_software_token(
        AccessToken=self.access_token,
        UserCode=mfa_code
    )
    return response


def update_software_mfa(self, request, enabled):
    response = self.client.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': enabled
        },
        AccessToken=self.access_token
    )
    return response


def update_sms_mfa(self, request, enabled):
    response = self.client.set_user_mfa_preference(
        SMSMfaSettings={
            'Enabled': enabled
        },
        AccessToken=self.access_token
    )
    return response


def get_user_detailed(self):
    user = self.client.get_user(
            AccessToken=self.access_token
        )
    return user


register_method(auth_error_handler)
register_method(authenticate)
register_method(admin_disable_user)
register_method(admin_enable_user)
register_method(respond_to_auth_challenge)
register_method(associate_software_token)
register_method(verify_software_token)
register_method(update_software_mfa)
register_method(update_sms_mfa)
register_method(get_user_detailed)
