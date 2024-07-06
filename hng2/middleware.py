import jwt
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from api.models import User

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get('x-auth-token')
        if auth_header:
            try:

                payload = jwt.decode(auth_header, 'no cast am', algorithms=['HS256'])
                user = User.objects.get(id=payload['id'])
                request.user = user
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid token'}, status=401)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)
        else:
            request.user = None
        return None

