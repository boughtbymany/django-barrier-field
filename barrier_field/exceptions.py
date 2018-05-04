from warrant.exceptions import ForceChangePasswordException


class MFARequiredSMS(Exception):
    pass


class MFARequiredSoftware(Exception):
    pass


class CognitoUserNotFound(Exception):
    pass


class CognitoUserDisabled(Exception):
    pass


class CognitoIncorrectPassword(Exception):
    pass


class MFAMismatch(Exception):
    pass


catch_login_exceptions = (
    MFARequiredSMS, MFARequiredSoftware, ForceChangePasswordException
)
