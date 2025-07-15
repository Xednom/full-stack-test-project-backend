from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


class ConvertMeterToFeetView(APIView):
    """
    API endpoint to convert meters to feet
    Accepts JSON data via POST request only
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Handle POST requests with JSON body"""
        try:
            meters = request.data.get("meters")
            
            if meters is None:
                return Response(
                    {
                        "error": "meters parameter is required",
                        "usage": {
                            "POST": '{"meters": 10}',
                            "example": "Send a POST request with JSON body containing 'meters' field"
                        },
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Convert to float and validate
            try:
                meters_value = float(meters)
            except (ValueError, TypeError):
                return Response(
                    {"error": "meters must be a valid number"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if meters_value < 0:
                return Response(
                    {"error": "meters cannot be negative"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Convert meters to feet (1 meter = 3.28084 feet)
            feet_value = meters_value * 3.28084

            return Response(
                {
                    "meters": meters_value,
                    "feet": round(feet_value, 4),
                    "conversion_rate": "1 meter = 3.28084 feet",
                    "success": True
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}", "success": False},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    
    def get(self, request):
        """Return API documentation for GET requests"""
        return Response(
            {
                "message": "This endpoint only accepts POST requests with JSON data",
                "endpoint": "/api/v1/convert-meter-to-feet/",
                "method": "POST",
                "content_type": "application/json",
                "required_fields": {
                    "meters": "number (float or integer)"
                },
                "example_request": {
                    "meters": 10
                },
                "example_response": {
                    "meters": 10.0,
                    "feet": 32.8084,
                    "conversion_rate": "1 meter = 3.28084 feet",
                    "success": True
                }
            },
            status=status.HTTP_200_OK
        )
