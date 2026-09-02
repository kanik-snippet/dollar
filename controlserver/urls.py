from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("admin/", admin.site.urls),
    path("automation-admin/", admin.site.urls),
    path("", include("control.urls")),
]
