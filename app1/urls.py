from django.urls import path
from . import views


urlpatterns = [
    path('',views.SignUp, name='Signup'),
    path('login/',views.Login, name='Login'),
    path('home/',views.Home, name='Signup')
]
