"""CustomAuth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.http import JsonResponse

from authentication import token


def get_token(request, internal=False, **kwargs):
    kwargs.setdefault("user_unique_key", request.GET.get("username"))
    _token = token.get_token_for_user(request=request, **kwargs)

    if internal:
        return _token
    else:
        return JsonResponse({
            "token": _token
        })


def get_data_from_token(request):
    _get = request.GET
    try:
        return JsonResponse(token.validate_and_get_data(_get.get("t"), request))
    except Exception as e:  # NOQA
        return JsonResponse({"error": True, "message": str(e)})


urlpatterns = [
    path('admin/', admin.site.urls),
    path("", get_data_from_token),
    path("t/", get_token),
]
