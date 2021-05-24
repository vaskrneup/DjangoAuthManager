from django.core.signing import TimestampSigner, SignatureExpired
from django.conf import settings

signer = TimestampSigner()


class InvalidToken(Exception):
    pass


class TokenExpired(Exception):
    pass


def get_token_for_user(
        user_unique_key: str, request,
        identifiers: dict = None, user_data: dict = None
) -> str:
    return signer.sign_object({
        "k": user_unique_key,
        "l": request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR"),
        "i": (identifiers or {}),
        "d": (user_data or {})
    })


def validate_and_get_data(token, request, identifiers=None):
    try:
        data = signer.unsign_object(token, max_age=settings.TOKEN_AGE)

        user_loc = request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR")

        if user_loc != data.get("l") or data.get("i") != (identifiers or {}):
            raise InvalidToken("Either Token is tampered with or doesn't belong to the user.")
        else:
            return {
                "user_unique_key": data.get("k"),
                "user_location": data.get("l"),
                "user_data": data.get("d"),
                "user_optional_identifiers": data.get("i"),
            }
    except Exception as _:
        raise TokenExpired("Token expired or invalid token.")
