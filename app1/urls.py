from django.urls import path
from . import views

urlpatterns = [
    path('',views.SignUp, name='Signup'),
    path('login/',views.Login, name='Login'),
    path('home/',views.Home, name='home'),
    path('reqresetpassword/',views.request_password_reset, name='reqresetpassword'),
    path('verify_otp/',views.verify_otp, name='verify_otp'),
    path('resetpassword/',views.reset_password, name='reset_password')
]
