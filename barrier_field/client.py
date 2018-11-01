import boto3
from django.conf import settings

from jose import jwt
from jose.exceptions import JWTClaimsError, JWTError
from warrant import Cognito, AWSSRP, TokenVerificationException
from django.shortcuts import redirect
from django.urls import (reverse, reverse_lazy)
from warrant.exceptions import ForceChangePasswordException

from barrier_field.exceptions import MFARequiredSMS, MFARequiredSoftware, \
    MFAMismatch, CognitoInvalidPassword, UserNotConfirmed
from barrier_field.utils import get_user_model, get_user_data_model_fields, \
    get_user_data_model, aws_assume_role


class CognitoBarrierField(Cognito):
    def __init__(
            self, user_pool_id, client_id, user_pool_region=None,
            username=None, id_token=None, refresh_token=None,
            access_token=None, client_secret=None,
            access_key=None, secret_key=None, session_token=None,
            assume_role_arn=None,
    ):
        super(CognitoBarrierField, self).__init__(user_pool_id, client_id)
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.user_pool_region = self.user_pool_id.split('_')[0]
        self.username = username
        self.id_token = id_token
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client_secret = client_secret
        self.token_type = None
        self.custom_attributes = None
        self.base_attributes = None

        if assume_role_arn:
            self.client = boto3.client(
                'cognito-idp', **aws_assume_role(
                    access_key, secret_key, assume_role_arn
                )
            )
        else:
            boto3_client_kwargs = {}
            if access_key and secret_key:
                boto3_client_kwargs['aws_access_key_id'] = access_key
                boto3_client_kwargs['aws_secret_access_key'] = secret_key
            if session_token:
                boto3_client_kwargs['aws_session_token'] = session_token
            if user_pool_region:
                boto3_client_kwargs['region_name'] = user_pool_region

            self.client = boto3.client('cognito-idp', **boto3_client_kwargs)

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
                        {'username': self.username}, deactivate=True
                    )
                    return None
                if error['Message'] == 'Incorrect username or password.':
                    return None
            elif error['Code'] == 'UserNotFoundException':
                return None
            elif error['Code'] == 'CodeMismatchException':
                raise MFAMismatch()
            elif error['Code'] == 'InvalidPasswordException':
                raise CognitoInvalidPassword()
            elif error['Code'] == 'UserNotConfirmedException':
                raise UserNotConfirmed()
            raise exception
        else:
            raise exception

    def verify_token(self, token, id_name, token_use):
        kid = jwt.get_unverified_header(token).get('kid')
        unverified_claims = jwt.get_unverified_claims(token)
        token_use_verified = unverified_claims.get('token_use') == token_use
        if not token_use_verified:
            raise TokenVerificationException(
                'Your {} token use could not be verified.')
        hmac_key = self.get_key(kid)
        try:
            verified = jwt.decode(token, hmac_key, algorithms=['RS256'],
                                  audience=unverified_claims.get('aud'),
                                  issuer=unverified_claims.get('iss'))
        except JWTClaimsError:
            verified = jwt.decode(
                token, hmac_key, algorithms=['RS256'],
                audience=unverified_claims.get('aud'),
                issuer=unverified_claims.get('iss'),
                access_token=self.access_token
            )
        except JWTError:
            raise TokenVerificationException(
                'Your {} token could not be verified.')
        setattr(self, id_name, token)
        return verified

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
        auth_params = aws.get_auth_params()
        tokens = self.client.initiate_auth(
            AuthFlow='USER_SRP_AUTH',
            AuthParameters=auth_params,
            ClientId=self.client_id
        )
        if tokens.get('ChallengeName'):
            challenge_type = tokens['ChallengeName']
            request.session['AUTH_CHALLENGE'] = tokens

            # Handle force changing passwords
            if challenge_type == aws.PASSWORD_VERIFIER_CHALLENGE:
                challenge_response = aws.process_challenge(
                    tokens['ChallengeParameters'])
                tokens = self.client.respond_to_auth_challenge(
                    ClientId=self.client_id,
                    ChallengeName=aws.PASSWORD_VERIFIER_CHALLENGE,
                    ChallengeResponses=challenge_response)

                if (tokens.get('ChallengeName') ==
                        aws.NEW_PASSWORD_REQUIRED_CHALLENGE):
                    request.session['AUTH_CHALLENGE'] = tokens
                    raise ForceChangePasswordException()

            # Handle MFA
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

    def admin_create_user(self, data):
        self.client.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=data['username']
        )

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

    def change_password(self, request, current_password, new_password):
        response = self.client.change_password(
            AccessToken=request.session['cognito_auth']['access_token'],
            PreviousPassword=current_password,
            ProposedPassword=new_password
        )

        return response

    def force_change_password_challenge(self, session, username, new_password):
        """
        Respond to the new password challenge using the SRP protocol
        :param password: The user's current passsword
        :param password: The user's new passsword
        """
        tokens = self.client.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            Session=session,
            ChallengeResponses={
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            }
        )
        self.id_token = tokens['AuthenticationResult']['IdToken']
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.access_token = tokens['AuthenticationResult']['AccessToken']
        self.token_type = tokens['AuthenticationResult']['TokenType']

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

    def sync_cache(self, cognito_user, deactivate=False):
        """
        Check and update local user data, and sync with cognito data if needed
        :param cognito_user:
        :param deactivate: if True, is_active of local user will be set to
        False. This will be run in the case of the cognito user being disabled.
        :return:
        """
        Users = get_user_model()

        if deactivate:
            local_user = Users.objects.get(
                username=cognito_user['username']
            )
            local_user.is_active = False
            local_user.save()
        else:
            try:
                local_user = Users.objects.get(email=cognito_user.pk)
                if not local_user.is_active:
                    # Reactive user
                    local_user.is_active = True

                cognito_data = cognito_user._data

                user_data_fields = get_user_data_model_fields()
                if user_data_fields:
                    user_data_update = {}
                    for field in [*cognito_data.keys()].copy():
                        if field in user_data_fields:
                            user_data_update[field] = cognito_data.pop(field)

                    # Update user data
                    user_data_object = get_user_data_model().objects.filter(
                        pk=local_user.user_data_id
                    )
                    user_data_object.update(**user_data_update)

                for field in cognito_data.keys():
                    cognito_field_value = getattr(cognito_user, field)
                    if isinstance(getattr(local_user, field), bool):
                        cognito_field_value = bool(int(cognito_field_value))
                    setattr(local_user, field, cognito_field_value)

                local_user.save()
            except Users.DoesNotExist:
                # Create new cached user

                # First check whether a custom data model exists
                user_data_fields = get_user_data_model_fields()
                if user_data_fields:
                    compiled_user_data = {}
                    for field in user_data_fields:
                        if field in cognito_user._data.keys():
                            user_data = cognito_user._data.pop(field)
                            compiled_user_data[field] = user_data
                    user_data = get_user_data_model().objects.create(
                        **compiled_user_data
                    )

                    Users.objects.create_user(
                        username=cognito_user.username, password=None,
                        user_data=user_data, **cognito_user._data
                    )
                else:
                    Users.objects.create_user(
                        username=cognito_user.username, password=None,
                        **cognito_user._data
                    )


def cognito_client(request=None):
    cognito = CognitoBarrierField(
        settings.COGNITO_USER_POOL_ID,
        settings.COGNITO_APP_ID,
        access_key=getattr(settings, 'AWS_ACCESS_KEY_ID', None),
        secret_key=getattr(settings, 'AWS_SECRET_ACCESS_KEY', None),
        session_token=getattr(settings, 'AWS_SESSION_TOKEN', None),
        assume_role_arn=getattr(settings, 'ASSUME_ROLE_ARN', None)
    )
    if request:
        cognito_session = request.session.get('cognito_auth')
        if cognito_session:
            cognito_auth_session = request.session['cognito_auth']
            cognito.access_token = cognito_auth_session['access_token']
            cognito.refresh_token = cognito_auth_session['refresh_token']
            cognito.token_type = cognito_auth_session['token_type']
            cognito.id_token = cognito_auth_session['id_token']
    return cognito
