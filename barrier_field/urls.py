"""policies_io_warrant URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib.auth.decorators import login_required
from django.urls import path

from barrier_field import views

urlpatterns = [
    path('register/', views.Register.as_view(), name='register'),
    path('update/', views.Update.as_view(), name='update'),
    path('login/', views.login_view, name='cognito-login'),
    path('logout/', views.logout_view, name='cognito-logout'),
    path(
        'mfa-settings/',
        login_required(views.MFASettings.as_view()),
        name='mfa-settings'
    ),
    path('sms-mfa/', views.SMSMFA.as_view(), name='sms-mfa'),
    path('software-mfa/', views.SoftwareMFA.as_view(), name='software-mfa'),
    path('associate-mfa/', views.SetSoftwareMFA.as_view(), name='associate-mfa'),
    path(
        'update-password/',
        views.ForceChangePassword.as_view(),
        name='force-change-password'
    ),

]
