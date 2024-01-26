from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
import random
import re
from django.conf import settings

# Create your views here.
@login_required(login_url="login")
def Home(request):
    return render(request, 'home.html')

def check_password(pass_word):
    if re.search(r'[A-Z]',pass_word) and re.search(r'\d',pass_word) and re.search(r'[!@#$%^&*(),.?":{}|<>]',pass_word) and len(pass_word) >= 8:
        return True
    return False
        

def Login(request):
    if request.method == 'POST':
        user_name = request.POST.get('username')
        pass_w = request.POST.get('password')
        user = authenticate(request,username=user_name,password=pass_w)
        print(user_name,pass_w)
        if user is not None:
            login(request,user)
            messages.success(request, 'Login successful.')
            return redirect('home')
        else:
            messages.error(request, 'Incorrect email or password')
            return render(request, 'login.html')
    return render(request, 'login.html')
 
def SignUp(request):
    if request.method == 'POST':
        user_name = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if check_password(password):
            if password == confirm_password:
                my_user = User.objects.create_user(user_name,email, password)
                my_user.save()
                return redirect('/login')
            else:
                messages.error(request,"Your password does not match")
                return redirect('/')
        else:  
            messages.error(request,"Your password must satisfies the given conditions")
            return redirect('/')
    return render(request, 'signup.html')

def logout_view(request):
    auth_logout(request)
    return redirect('/login')

def request_password_reset(request):
    if request.method == 'POST':
        user_name = request.POST.get('username')
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if not user:
            user = User.objects.filter(username=user_name).first()
        if user:
            # Generate OTP
            otp = ''.join(random.choices('0123456789', k=4))
            print(otp)

            # Save OTP to user's profile (you may need to create a model for this)
            user.profile.reset_otp = otp
            user.profile.save()

            # Send OTP to user's email
            
            # send_mail(
            #     'Password Reset OTP',
            #     f'Your OTP for password reset is: {otp}',
            #     settings.EMAIL_HOST_USER,
            #     [user.email],
            #     fail_silently=False,
            # )

            return redirect('/verify_otp')
        else:
            messages.error(request, 'User not found.')
            return render(request, 'request_password_reset.html')
    return render(request, 'request_password_reset.html')

def verify_otp(request):
    if request.method == "POST":
        first = request.POST.get('first')
        second = request.POST.get('second')
        third = request.POST.get('third')
        fourth = request.POST.get('fourth')
        
        otp_entered = str(first) + str(second)+ str(third) + str(fourth)
        user = request.user
        if len(otp_entered) == 4:
            print(otp_entered)
            if user.profile.reset_otp == otp_entered:
            # OTP verification successful
                return redirect('reset_password')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                return render(request, 'verify_otp.html') 
        else:
            return render(request, 'verify_otp.html')     
    return render(request, 'verify_otp.html')

def reset_password(request):
    if request.method == "POST":
        new_password = request.POST.get('password')
        conf_pass_wd = request.POST.get('confirm_password')
        if check_password(new_password):
            if new_password == conf_pass_wd:
                user = request.user  # Assuming user is logged in
                if user.is_authenticated():
                    user.set_password(new_password)
                    user.save()
                    messages.success(request,"Your password has been reset successfully.")
                    return redirect('/login')
                else:
                    messages.error(request,"Your password does not match")
                    return redirect('/resetpassword')    
            else:
                messages.error(request,"Your password does not match")
                return redirect('/resetpassword')
        else:  
            messages.error(request,"Your password must satisfies the given conditions")
            return redirect('/resetpassword')
        
    return render(request, 'reset_password.html')