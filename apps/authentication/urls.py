from django.urls import path, include

from apps.authentication.social_media.google import GoogleLogin

app_name = "authentication"

urlpatterns = [
    path("", include("dj_rest_auth.urls")),
    path("registration/", include("dj_rest_auth.registration.urls")),
    path("social/", include("allauth.socialaccount.urls")),
    path("google/", GoogleLogin.as_view(), name="google_login"),
]
