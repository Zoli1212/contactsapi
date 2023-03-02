import jwt
from rest_framework import authentication, exceptions
from django.conf import settings
from django.contrib.auth.models import User


class JWTAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        auth_data = authentication.get_authorization_header(request)

        if not auth_data:
            return None

        prefix, token = auth_data.decode('utf-8').split(' ')
        print(token)

        try:
            print(settings.JWT_SECRET_KEY)
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            print(payload)
            


            user = User.objects.get(username=payload['username'])
            return (user, token)

        except jwt.exceptions.DecodeError:
            raise exceptions.AuthenticationFailed('Invalid token')
        except jwt.exceptions.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token has expired')
        except jwt.exceptions.InvalidTokenError:
            raise exceptions.AuthenticationFailed('Invalid token')

        return super().authenticate(request)