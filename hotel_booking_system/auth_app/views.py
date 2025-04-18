from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import CustomUser, WebsiteFeedback
from django.contrib.auth import get_user_model
from .forms import WebsiteFeedbackForm
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

def home_view(request):
    reviews = WebsiteFeedback.objects.all().order_by('-submitted_at')[:5]
    for review in reviews:
        review.star_range = range(1, 6)  # Add a range of 5 stars
    guest_range = range(1, 7)  # This gives [1, 2, 3, 4, 5, 6]
    return render(request, 'home.html', {'guest_range': guest_range, 'reviews': reviews})

def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        role = request.POST['role']
        age = request.POST['age']  # Assuming age is a required field

        # Validate if password matches confirm password
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        # Validate password strength
        try:
            validate_password(password)  # This uses Django's built-in validators
        except ValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return redirect('signup')

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect('signup')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password, role=role)

        # Automatically make admin if role is admin
        if role == 'admin':
            user.is_staff = True
            user.save()

        messages.success(request, 'Account created successfully. Please log in.')
        return redirect('login')
    
    return render(request, 'auth_app/signup.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, "Both fields are required.")
            return render(request, 'auth_app/login.html')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            messages.success(request, f"Welcome back, {user.username}!")

            if user.is_staff:
                return redirect('admin_dashboard')
            else:
                return redirect('user_dashboard')
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'auth_app/login.html')

def logout_view(request):
    logout(request)
    return redirect('login')



def feedback_before_logout(request):
    if request.method == 'POST':
        rating = request.POST.get('rating')
        comment = request.POST.get('comment')

        # If rating is provided, store it, otherwise leave it blank or None
        if rating:
            rating = int(rating)
        else:
            rating = None  # or you can leave it as None if not provided

        if comment:
            WebsiteFeedback.objects.create(
                user=request.user,
                rating=rating,
                comment=comment
            )
            messages.success(request, "Thank you for your feedback!")
        else:
            messages.warning(request, "Please provide a comment before submitting feedback.")

        logout(request)
        return redirect('home')
    
    return render(request, 'auth_app/feedback_form.html')


