import requests
import logging
import json
import base64
from django.core.exceptions import ValidationError

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.google.provider import GoogleProvider
from allauth.socialaccount.models import SocialToken
from dj_rest_auth.registration.views import SocialLoginView

logger = logging.getLogger(__name__)


class CustomGoogleOAuth2Adapter(GoogleOAuth2Adapter):
    provider_id = GoogleProvider.id

    def complete_login(self, request, app, token, **kwargs):
        """
        Returns a SocialLogin instance populated with account data.
        """
        try:
            # Log the token for debugging (first 10 chars only for security)
            logger.info(
                f"Attempting to get user info with token: {str(token.token)[:10]}..."
            )
            logger.info(f"Token type: {type(token.token)}")

            # Ensure token is a string and not empty
            access_token = str(token.token).strip()
            if not access_token or access_token == "dummy-access-token":
                logger.error("Invalid or dummy access token")
                raise ValidationError("Invalid access token provided")

            # Check if this is an ID token (JWT format) or access token
            if self._is_jwt_token(access_token):
                logger.info("Detected JWT/ID token, extracting user info from token")
                extra_data = self._decode_id_token(access_token)
            else:
                logger.info("Detected access token, fetching user info from Google API")
                extra_data = self._fetch_user_info_with_access_token(access_token)

            logger.info(
                f"Successfully retrieved user data for: {extra_data.get('email', 'unknown')}"
            )

            # Create a social login instance
            login = self.get_provider().sociallogin_from_response(request, extra_data)
            return login

        except requests.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise ValidationError(f"Failed to obtain user info from Google: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            raise ValidationError(f"Error processing Google login: {str(e)}")

    def _is_jwt_token(self, token):
        """Check if token is a JWT (has 3 parts separated by dots)"""
        return len(token.split(".")) == 3

    def _decode_id_token(self, id_token):
        """Decode Google ID token to get user info"""
        try:
            # Split the token into parts
            parts = id_token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid ID token format")

            # Decode the payload (second part)
            payload = parts[1]
            # Add padding if needed
            payload += "=" * (4 - len(payload) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload)
            user_data = json.loads(decoded_bytes.decode("utf-8"))

            logger.info(f"Decoded ID token data: {list(user_data.keys())}")
            return user_data

        except Exception as e:
            logger.error(f"Failed to decode ID token: {str(e)}")
            raise ValidationError(f"Invalid ID token: {str(e)}")

    def _fetch_user_info_with_access_token(self, access_token):
        """Fetch user info using access token from Google API"""
        logger.info(f"Fetching user info with token: {access_token[:20]}...")

        # First try: Bearer token in Authorization header (most common)
        try:
            resp = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )

            logger.info(
                f"Bearer token - Google API response status: {resp.status_code}"
            )

            if resp.status_code == 200:
                logger.info("Successfully authenticated with Bearer token")
                return resp.json()
            else:
                logger.error(f"Bearer token failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Bearer token request failed: {str(e)}")

        # Second try: access_token as query parameter
        try:
            resp = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                params={"access_token": access_token},
                timeout=10,
            )

            logger.info(f"Query param - Google API response status: {resp.status_code}")

            if resp.status_code == 200:
                logger.info("Successfully authenticated with query parameter")
                return resp.json()
            else:
                logger.error(f"Query param failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Query param request failed: {str(e)}")

        # Third try: Google's v3 tokeninfo endpoint to validate token
        try:
            resp = requests.get(
                "https://www.googleapis.com/oauth2/v3/tokeninfo",
                params={"access_token": access_token},
                timeout=10,
            )

            logger.info(f"Tokeninfo - Google API response status: {resp.status_code}")

            if resp.status_code == 200:
                token_info = resp.json()
                logger.info(f"Token info: {token_info}")

                # If token is valid, try to get user info with userinfo endpoint again
                if "scope" in token_info and "email" in token_info.get("scope", ""):
                    # Try userinfo with different approach
                    resp_userinfo = requests.get(
                        "https://www.googleapis.com/oauth2/v2/userinfo",
                        headers={
                            "Authorization": f"Bearer {access_token}",
                            "Accept": "application/json",
                        },
                        timeout=10,
                    )
                    if resp_userinfo.status_code == 200:
                        return resp_userinfo.json()
            else:
                logger.error(f"Tokeninfo failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Tokeninfo request failed: {str(e)}")

        # If all methods fail, raise an error
        raise ValidationError(
            "Failed to authenticate with Google API. "
            "Please check if the access token is valid and has the required scopes (email, profile)."
        )

    def parse_token(self, data):
        """
        Parse the token data from the frontend.
        """
        logger.info(f"Received token data keys: {list(data.keys())}")

        access_token = data.get("access_token")
        if not access_token:
            logger.error("No access token provided in request data")
            logger.error(f"Full data received: {data}")
            raise ValidationError("Access token is required")

        logger.info(f"Parsing token: {access_token[:10]}...")

        token = SocialToken(
            token=access_token,
            token_secret="",  # Google doesn't use token secrets
        )

        # Store additional token data if available
        if "expires_in" in data:
            from datetime import datetime, timedelta

            token.expires_at = datetime.now() + timedelta(
                seconds=int(data["expires_in"])
            )
            logger.info(f"Token expires at: {token.expires_at}")

        return token


class GoogleLogin(SocialLoginView):
    adapter_class = CustomGoogleOAuth2Adapter

    def post(self, request, *args, **kwargs):
        """
        Override post method to handle token data properly
        """

        # Handle different token formats from frontend
        if "access_token" not in request.data:
            # Check if token is nested in other fields
            if "token" in request.data:
                request.data["access_token"] = request.data["token"]
            elif "credential" in request.data:
                # Google's newer flow often sends credential (ID token)
                logger.info(
                    "Received credential (likely ID token), converting to access_token"
                )
                request.data["access_token"] = request.data["credential"]
            elif "id_token" in request.data:
                # If only id_token is provided, use it as access_token
                logger.info("Received id_token, converting to access_token")
                request.data["access_token"] = request.data["id_token"]
            else:
                logger.error(
                    f"No valid token found in request data: {list(request.data.keys())}"
                )

        # Log the token format for debugging
        if "access_token" in request.data:
            token = request.data["access_token"]
            logger.info(
                f"Token format check - Length: {len(token)}, Starts with: {token[:10]}..."
            )
            # Check if it's a JWT format (3 parts separated by dots)
            if "." in token and len(token.split(".")) == 3:
                logger.info("Token appears to be JWT format (ID token)")
            else:
                logger.info("Token appears to be regular access token format")

        return super().post(request, *args, **kwargs)
