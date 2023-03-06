# from django.shortcuts import render
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework_httpsignature.authentication import SignatureAuthentication
# from django.contrib.auth import authenticate
# from .models import *

# from rest_framework_httpsignature.authentication import SignatureAuthentication

# class MyAPISignatureAuthentication(SignatureAuthentication):
#     # The HTTP header used to pass the consumer key ID.
#     # Defaults to 'X-Api-Key'.
#     API_KEY_HEADER = 'X-Api-Key'

#     # A method to fetch (User instance, user_secret_string) from the
#     # consumer key ID, or None in case it is not found.
#     def fetch_user_data(self, api_key):
#         # ...
#         # example implementation:
#         try:
#             user = User.objects.get(api_key=api_key)
#             return (user, user.secret)
#         except User.DoesNotExist:
#             return None

from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
# from django.core.urlresolvers import reverse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse

class LoginView(APIView):
    authentication_classes = [SessionAuthentication]

    def post(self, request, format=None):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return Response({'message': 'Login successful.'})
            else:
                return Response({'error': 'User account is disabled.'})
        else:
            return Response({'error': 'Invalid login credentials.'})

class MyAPIView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Only authenticated users can access this endpoint
        data = {'message': f'Hello, {request.user.username}!'}
        return Response(data)

@ensure_csrf_cookie
def set_csrf_token(request):
    """
    This will be `/api/set-csrf-cookie/` on `urls.py`
    """
    return JsonResponse({"details": "CSRF cookie set"})