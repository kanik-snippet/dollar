from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("automation-admin/", admin.site.urls),
    path("", include("control.urls")),
]
