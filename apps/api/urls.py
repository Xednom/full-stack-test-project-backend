from django.urls import path

from apps.api.views import ConvertMeterToFeetView

app_name = "api"

urlpatterns = [
    path(
        "convert-meter-to-feet/",
        ConvertMeterToFeetView.as_view(),
        name="convert_meter_to_feet",
    ),
]
