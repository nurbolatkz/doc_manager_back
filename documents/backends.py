# myapp/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
import requests
import json
import base64
from django.views import View

UserModel = get_user_model()

# Create a proxy class with the same redirection logic as Base1CView
# The backend will use this class to make the login request to 1C.
class OneCAuthProxy(View):
    admin_login = "Администратор"
    admin_password = "ckfdbyf"
    one_c_path = "Ag_Tech_Mobile"
    one_c_server_url = "https://1c-dev.kazuni.kz/Ag_Tech_Web/"

    def _prepare_headers(self):
        userpass = f"{self.admin_login}:{self.admin_password}".encode("utf-8")
        basic_auth = base64.b64encode(userpass).decode("ascii")
        return {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/json"
        }

    def _call_1c_endpoint(self, request, method, address_path, additional_params=None):
        redirect_url = f"{self.one_c_server_url}hs/MobileExchange/redirection/"
        
        json_body = {
            "Метод": method,
            "Адрес": address_path,
            **(additional_params or {})
        }
        
        try:
            response = requests.post(
                redirect_url,
                json=json_body,
                headers=self._prepare_headers()
            )
            return response
        except requests.RequestException:
            return None

class OneCAuthBackend(BaseBackend):
    """
    Custom backend to authenticate against the 1C system using the redirection logic.
    """
    def authenticate(self, request, username=None, password=None):
        proxy = OneCAuthProxy()
        
        address_path = f"http://localhost/{proxy.one_c_path}/hs/MobileExchange/request_handler/"
        
        payload = {
            "ТелоЗапроса": {
                "typeOfRequest": "login",
                "username": username,
                "password": password
            }
        }
        
        response = proxy._call_1c_endpoint(request, "POST", address_path=address_path, additional_params=payload)
        
        if response and response.status_code == 200:
            try:
                response_data = response.json()
                token = response_data.get('token')
                
                if token:
                    user, created = UserModel.objects.get_or_create(username=username)
                    user.is_active = True
                    user.set_unusable_password()
                    user.save()
                    
                    request.session['1c_token'] = token
                    request.session.set_expiry(3600)  # Set session expiry to 1 hour
                    print(f"User {username} authenticated successfully with token: {token}")
                    return user
            except json.JSONDecodeError:
                pass
        
        return None

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None