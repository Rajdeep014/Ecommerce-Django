from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout

def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        if password != confirm_password:
            messages.warning(request, "Passwords do not match.")
            return render(request, 'signup.html')

        if User.objects.filter(username=email).exists():
            messages.error(request, "User already exists.")
            return redirect('signup')

        if len(password) < 8:
            messages.warning(request, "Password must be at least 8 characters long.")
            return render(request, 'signup.html')

        if not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            messages.warning(request, "Password must include both letters and numbers.")
            return render(request, 'signup.html')

        user = User.objects.create_user(username=email, email=email, password=password)
        user.save()
        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login')

    return render(request, "signup.html")


def handlelogin(request):
    if request.method == 'POST':
        username = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful.")
            return redirect('/')
        else:
            messages.error(request, "Invalid email or password.")
            return redirect('auth/login/')

    return render(request,"login.html")


def handlelogout(request):
    logout(request)
    messages.success(request, "Logout successful.")
    return render(request,'login.html')
