from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, update_session_auth_hash, logout
from django.contrib.auth.hashers import make_password
from .utils import *



class Authentication:
    @login_required

    @never_cache
    def Dashboard(request):
        return render(request, "Dashboard.html")

    @never_cache
    def login(request):
        # Clear old session data
        if request.method == 'GET':
            request.session.flush()

        email = ''
        pswd = ''
        error_email = ''
        error_pswd = ''

        if request.method == 'POST':
            email = request.POST.get('email', '').strip()
            pswd = request.POST.get('pswd', '').strip()

            if error := validate_email(email):
                error_email = error
            elif error := validate_password(pswd):
                error_pswd = error
            else:
                try:
                    user = User.objects.get(email=email)
                    authenticated_user = authenticate(request, username=user.username, password=pswd)
                    if authenticated_user:
                        auth_login(request, user)
                        request.session.save()
                        return redirect('Dashboard')
                    error_pswd = 'Invalid Password'
                except User.DoesNotExist:
                    error_email = 'Sign Up First'

            return render(request, 'login.html', {
                'active_tab': 'login',
                'form_data_email': email,
                'form_data_pswd': pswd,
                'error_email': error_email,
                'error_pswd': error_pswd,
            })

        return render(request, 'login.html', {
            'active_tab': 'login',
            'form_data_email': '',
            'form_data_pswd': '',
            'error_email': '',
            'error_pswd': '',
        })



    def signup(request):
        field_names = ['first_name', 'last_name', 'email', 'phone', 'pswd', 'confirm_pswd']
        format_hints = {
            'first_name': 'Only letters (e.g. "John")',
            'last_name': 'Only letters (e.g. "Doe")',
            'email': 'Format: example@domain.com',
            'phone': '10 digits starting with 6-9',
            'pswd': 'Minimum 8 characters with uppercase, lowercase and special character',
            'confirm_pswd': 'Must match password',
        }

        data = {field: '' for field in field_names}
        errors = {f'error_{field}': '' for field in field_names}

        if request.method == 'POST':
            storage = messages.get_messages(request)
            storage.used = True

            for field in field_names:
                data[field] = request.POST.get(field, '').strip()

            # Set individual errors
            errors['error_first_name'] = validate_name(data['first_name'], 'first name')
            errors['error_last_name'] = validate_name(data['last_name'], 'last name')
            errors['error_email'] = validate_email(data['email'], check_exists=True)
            errors['error_phone'] = validate_phone(data['phone'], check_exists=True)
            errors['error_pswd'] = validate_password(data['pswd'], data['confirm_pswd'])

            # If any error exists, re-render
            if any(errors.values()):
                return render(request, 'login.html', {
                    'active_tab': 'signup',
                    'format_hints': format_hints,
                    'field_names': field_names,
                    **{f'form_data_{k}': v for k, v in data.items()},
                    **errors,
                })

            try:
                username = generate_username(data['email'])

                # MySQL (default database)
                user = User.objects.db_manager('default').create_user(
                    username=username,
                    email=data['email'],
                    phone=data['phone'],
                    password=data['pswd'],
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                )

                # SQLite database
                User.objects.db_manager('sqlite').create_user(
                    username=username,
                    email=data['email'],
                    phone=data['phone'],
                    password=data['pswd'],
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                )

                auth_login(request, user)
                messages.success(request, 'Account created successfully!')
                return redirect('login')


                # username = generate_username(data['email'])
                # user = User.objects.create_user(
                #     username=username,
                #     email=data['email'],
                #     phone=data['phone'],
                #     password=data['pswd'],
                #     first_name=data['first_name'],
                #     last_name=data['last_name'],
                # )
                # auth_login(request, user)
                # messages.success(request, 'Account created successfully!')
                # return redirect('login')


            except Exception as e:
                messages.error(request, f'Error creating account: {str(e)}')
                return render(request, 'login.html', {
                    'active_tab': 'signup',
                    'format_hints': format_hints,
                    'field_names': field_names,
                    **{f'form_data_{k}': v for k, v in data.items()},
                    **errors,
                })

        return render(request, 'login.html', {
            'active_tab': 'login',
            'format_hints': format_hints,
            'field_names': field_names,
            **{f'form_data_{k}': '' for k in field_names},
            **errors,
        })


    @login_required
    @never_cache
    def logout_user(request):
        # Flush session and logout
        request.session.flush()
        request.session.clear()
        logout(request)

        # Delete cookies
        response = redirect('login')
        response.delete_cookie('sessionid')
        response.delete_cookie('csrftoken')

        # Create response with cache-control headers
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'

        messages.success(request, 'Logged out successfully')
        return response


    def forgot_password(request):
        msg = []
        step = request.session.get('step', 'send_otp')
        email = request.session.get('email')

        if request.method == 'POST':
            if 'send_otp' in request.POST:
                email_input = request.POST.get('email').strip()
                try:
                    User.objects.get(email=email_input)
                    success, error = send_otp_email(request, email_input)
                    if success:
                        request.session['email'] = email_input
                        request.session['step'] = 'verify_otp'
                        request.session['otp_expired'] = False  # reset flag
                        messages.success(request, 'OTP sent to your email.')
                        return redirect('forget')
                    else:
                        messages.error(request, error)
                except User.DoesNotExist:
                    messages.error(request, 'No user with this email.')
                return redirect('forget')


            elif 'verify_otp' in request.POST:
                otp_input = request.POST.get('otp').strip()

                success, error, otp_expired = verify_otp(request, otp_input)

                if success:
                    request.session['step'] = 'reset_password'
                    request.session['otp_expired'] = False
                    messages.success(request, 'OTP verified. Now reset your password.')
                else:
                    request.session['otp_expired'] = otp_expired   # <-- Ye line add karo
                    messages.error(request, error)

                return redirect('forget')

            # elif 'verify_otp' in request.POST:
            #     otp_input = request.POST.get('otp').strip()
            #     # success, error = verify_otp(request, otp_input)
            #     success, error, otp_expired = verify_otp(request, otp_input)
            #     if success:
            #         request.session['step'] = 'reset_password'
            #         request.session['otp_expired'] = False
            #         messages.success(request, 'OTP verified. Now reset your password.')
            #     else:
            #         messages.error(request, error)
            #     return redirect('forget')

            elif 'resend_otp' in request.POST:
                email = request.session.get('otp_email') or request.session.get('email')
                if not email:
                    messages.error(request, 'Session expired. Please start again.')
                    return redirect('forget')
                success, error = send_otp_email(request, email)
                if success:
                    request.session['step'] = 'verify_otp'
                    request.session['otp_expired'] = False
                    messages.success(request, 'New OTP sent to your email.')
                else:
                    messages.error(request, error)
                return redirect('forget')

            elif 'reset_password' in request.POST:
                password = request.POST.get('password')
                confirm = request.POST.get('confirm')
                if error := validate_password(password, confirm):
                    messages.error(request, error)
                else:
                    user = User.objects.get(email=email)
                    user.password = make_password(password)
                    user.save()
                    request.session.flush()
                    messages.success(request, 'Password reset successfully.')
                    return redirect('login')

        return render(request, 'forget.html', {
            'step': step,
            'msg_list': msg,
            'otp_expired': request.session.get('otp_expired', False),
        })


    @login_required
    def change_password(request):
        msg = []
        if request.method == 'POST':
            old_password = request.POST.get('old_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if not request.user.check_password(old_password):
                messages.error(request, 'Your current password is incorrect')
            elif error := validate_password(new_password, confirm_password):
                messages.error(request, error)
            else:
                try:
                    request.user.set_password(new_password)
                    request.user.save()
                    update_session_auth_hash(request, request.user)
                    messages.success(request, 'Password changed successfully!')
                    return redirect('change_password')
                except Exception as e:
                    messages.error(request, f'Error changing password: {str(e)}')
        return render(request, 'change_password.html', {'msg_list': msg})