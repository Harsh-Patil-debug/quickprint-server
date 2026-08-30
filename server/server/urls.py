"""QuickPrint — Root URL Configuration"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse


def home_view(request):
    return JsonResponse({
        "message": "QuickPrint API is running.",
        "version": "v1",
        "docs": "Use /api/v1/main/ endpoints"
    })


urlpatterns = [
    path('', home_view, name='home'),
    path('admin/', admin.site.urls),
    path('api/v1/main/', include('quickprint_project.main.urls', namespace='main_v1')),
]
