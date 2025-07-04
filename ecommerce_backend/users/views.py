from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import EmailMessage
from django.conf import settings
from .models import User, Address
from .serializers import (
    RegisterSerializer, UserSerializer,
    ChangePasswordSerializer, AddressSerializer
)

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import EmailMessage
from django.conf import settings
from .serializers import RegisterSerializer

def clean_text(text):
    if not text:
        return ''
    return text.replace('\xa0', ' ').strip()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.generate_otp()
            user.is_verified = False
            user.save(update_fields=['is_verified'])

            subject = "Your OTP Code"
            from_email = clean_text(settings.DEFAULT_FROM_EMAIL)
            recipient_list = [user.email]

            clean_name = clean_text(user.name)
            clean_otp = clean_text(str(user.otp))
            message = f"Hello {clean_name}, your OTP is {clean_otp}."
            print("From email:", repr(from_email))
            print("User name:", repr(user.name))
            print("OTP:", repr(user.otp))
            print("Message:", repr(message))


            try:
                email = EmailMessage(
                    subject=subject,
                    body=message,
                    from_email=from_email,
                    to=recipient_list
                )
                email.content_subtype = "plain"
                email.encoding = 'utf-8'
                email.send()
            except Exception as e:
                return Response(
                    {"error": "Failed to send OTP email", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response({"message": "User registered successfully. OTP sent to email."}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ✅ Profile View (Get & Update)
class ProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


# ✅ Change Password
class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        user = request.user

        if serializer.is_valid():
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({'old_password': 'Incorrect password'}, status=400)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': 'Password changed successfully'})
        return Response(serializer.errors, status=400)


# ✅ Address List & Create
class AddressListCreateView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AddressSerializer

    def get_queryset(self):
        return Address.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# ✅ Address Retrieve, Update, Delete
class AddressDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AddressSerializer

    def get_queryset(self):
        return Address.objects.filter(user=self.request.user)


from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # ✅ Prevent login if email not verified
        if not self.user.is_verified:
            raise serializers.ValidationError("Email is not verified. Please verify your email before login.")

        # ✅ Add extra user info to response
        data['role'] = self.user.role
        data['name'] = self.user.name
        data['email'] = self.user.email

        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User

class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'error': 'Email and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if user.otp != otp:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        if user.otp_is_expired():
            return Response({'error': 'OTP expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        # OTP valid and not expired - verify user
        user.is_verified = True
        user.otp = None
        user.otp_created_at = None
        user.save(update_fields=['is_verified', 'otp', 'otp_created_at'])
        return Response({'message': 'OTP verified successfully.'}, status=status.HTTP_200_OK)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMessage
from django.conf import settings
from .models import User

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({'message': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate new OTP and update timestamp
        user.generate_otp()

        # Send OTP email
        subject = "Your new OTP Code"
        message = f"Hello {user.name}, your new OTP is {user.otp}."
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]

        try:
            email_message = EmailMessage(subject=subject, body=message, from_email=from_email, to=recipient_list)
            email_message.content_subtype = "plain"
            email_message.encoding = 'utf-8'
            email_message.send()
        except Exception as e:
            return Response({"error": "Failed to send OTP email", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "New OTP sent to email."}, status=status.HTTP_200_OK)
