from django.contrib import admin
from django.urls import path,include
from .views import *

urlpatterns = [
    path('login/', LoginView.as_view()),
    path('myview/', MyAPIView.as_view()),
    path('set-csrf/', set_csrf_token, name='Set-CSRF'),
]