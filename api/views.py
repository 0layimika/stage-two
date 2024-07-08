from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import User,Organisation
from .serializers import UserSerializer, OrgSerializer
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import bcrypt
import jwt, datetime
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from django.http import HttpResponse
class RegisterView(APIView):
    def post(self, request):
        data = request.data
        if not data.get('firstName') or not isinstance(data.get('firstName'), str):
            return Response({'errors':[{'field':"firstName", 'message':"firstName is required as string"}]}, status=status.HTTP_400_BAD_REQUEST)
        if not data.get('lastName') or not isinstance(data.get('lastName'), str):
            return Response({'errors':[{'field':"lastName", 'message':"lastName is required as string"}]}, status=status.HTTP_400_BAD_REQUEST)
        if not data.get('email'):
            return Response({'errors':[{'field':"email", 'message':"email address is reequired as email"}]}, status=status.HTTP_400_BAD_REQUEST)
        if not data.get('password') or not isinstance(data.get('password'), str):
            return Response({'errors':[{'field':"password", 'message':"password is required as string"}]}, status=status.HTTP_400_BAD_REQUEST)
        if data.get('phone') is not None and not isinstance(data.get('phone'), str):
            return Response({'errors':[{'field':"phone", 'message':"phone is required as string"}]}, status=status.HTTP_400_BAD_REQUEST)
        try:
            validate_email(data.get('email'))
        except ValidationError:
            return Response({
                "status": "Bad Request",
                "message": "Registration failed",
                "statusCode":400
            }, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=data.get('email')).exists():
            return Response({
                "status": "Bad Request",
                "message": "Registration failed",
                "statusCode":400
            }, status=status.HTTP_400_BAD_REQUEST)
        password = data.get("password")
        encrypted = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            user = User.objects.create(firstName=data.get('firstName'), lastName = data.get('lastName'), email=data.get('email'), password = encrypted, phone=data.get("phone") )
            organisation = Organisation.objects.create(name=f"{data.get('firstName')}'s organisation")
            organisation.users.add(user)
            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)
            return Response({
                "status":"success",
                "message":"Registration Successful",
                "data":{
                    "accessToken":token,
                    "user":UserSerializer(user).data
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(e)
            return Response({
                "status": "Bad Request",
                "message": "Registration failed",
                "statusCode":400
            }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        data = request.data
        try:
            try:
                user = User.objects.get(email=data.get('email'))
                print(user)
            except User.DoesNotExist:
                return Response({
                    'status': "Bad request",
                    'message': "Authentication Failed",
                    'statusCode': 401
                }, status=status.HTTP_401_UNAUTHORIZED)
            if bcrypt.checkpw(data.get('password').encode('utf-8'), user.password.encode('utf-8')):
                refresh = RefreshToken.for_user(user)
                token = str(refresh.access_token)
                return Response({
                    "status": "success",
                    "message": "Authentication successful",
                    "data": {
                        "accessToken": token,
                        "user":UserSerializer(user).data}
                })
            return Response({
                'status': "Bad request",
                'message': "Authentication failed",
                'statusCode': 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            return Response({
                'status': "Bad request",
                'message': "Authentication failed",
                'statusCode': 401
            }, status=status.HTTP_401_UNAUTHORIZED)


class UserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, id):
        try:
            user = User.objects.get(userId=id)
            if request.user == user or request.user.organisations.filter(users=user).exists() or Organisation.objects.filter(users=request.user).filter(users=user).exists():
               return Response({
                   'status':'success',
                   'message':'User retrieved successfully',
                   'data':UserSerializer(user).data
               })
            return Response({
                'status':'Forbidden',
                'message':'You do not have access to this data',
                'statusCode':'403'
            }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({
                'status':'Not Found',
                'message':'User not found',
                'statusCode':404
            }, status=status.HTTP_404_NOT_FOUND)

@method_decorator(csrf_exempt, name='dispatch')
class OrganisationsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            organisations = request.user.organisations
            return Response({
                "status": "success",
                "message": "Organisations retrieved",
                "data": OrgSerializer(organisations, many=True).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({
                'status':'bad request',
                'message':'Retrieving failed',
                'statusCode':400
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def post(self, request):
        data = request.data
        user = User.objects.get(pk=request.user.id)
        try:
            name = data.get('name')
            description = data.get('description')
            if not name or not isinstance(name, str):
                return Response({
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            })
            if description is not None and not isinstance(description, str):
                return Response({
                    "status": "Bad Request",
                    "message": "Client error",
                    "statusCode": 400
                })
            organisation = Organisation.objects.create(name=name, description=description)
            organisation.users.add(user)
            organisation.save()
            return Response({
                "status": "success",
                "message": "Organisation created successfully",
                "data":OrgSerializer(organisation).data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(e)
            return Response({
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            })

class OrgView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, id):
        try:
            user = User.objects.get(pk=request.user.id)
            organisation = Organisation.objects.get(orgId=id)
            if user in organisation.users.all():

                return Response({
                    "status": "success",
                    "message": "Organisations retrieved",
                    "data": OrgSerializer(organisation).data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': 'forbidden',
                    'message': 'You do not have access to this information',
                    'statusCode': 404
                }, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            print(e)
            return Response({
                'status': 'bad request',
                'message': 'Retrieving failed',
                'statusCode': 400
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class addOrgView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, id):
        data = request.data
        userId = data.get('userId')

        # Validate userId
        if not userId or not isinstance(userId, str):
            return Response({
                "status": "Bad Request",
                "message": "Invalid userId",
                "statusCode": 400
            })

        try:
            # Retrieve user by userId
            user = User.objects.get(userId=userId)

            try:
                # Retrieve organisation by orgId
                organisation = Organisation.objects.get(orgId=id)

                # Check if user already exists in organisation
                if organisation.users.filter(userId=user.userId).exists():
                    return Response({
                        "status": "Bad Request",
                        "message": "User already exists in organisation"
                    })

                # Add user to organisation
                organisation.users.add(user)
                organisation.save()

                return Response({
                    "status": "success",
                    "message": "User added to organisation successfully",
                })

            except Organisation.DoesNotExist:
                return Response({
                    "status": "Not Found",
                    "message": "Organisation not found",
                    "statusCode": 404
                })

        except User.DoesNotExist:
            return Response({
                "status": "Not Found",
                "message": "User not found",
                "statusCode": 404
            })

        except Exception as e:
            print(e)
            return Response({
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            })


def home(request):
    return HttpResponse("dog")

