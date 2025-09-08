"""
URL configuration for dms_core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path, include
from django.shortcuts import redirect

# Root URL redirect view
def redirect_to_request_sender(request):
    return redirect('request_sender_to_1c')

urlpatterns = [
    # Root URL pattern
    #path('', redirect_to_request_sender, name='root'),
    path('admin/', admin.site.urls),
    
    path('', include('documents.urls')),  # Include URLs from the documents app
]
