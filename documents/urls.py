from django.urls import path
from documents.views import (
    MainPage1CView,RequestSenderTo1C, DocumentDetail1CView, LoginView, ProxyView)

urlpatterns = [
    #path('main/', MainPage1CView.as_view(), name='main_page'),
    path('api/', ProxyView.as_view(), name='api'),
    path('login/', LoginView.as_view(), name='login_view'),
    path('send_request_to_1c/', RequestSenderTo1C.as_view(), name='request_sender_to_1c'),
    
   
    
]