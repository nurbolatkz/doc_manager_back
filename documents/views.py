import json
import base64
import os
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse,HttpResponseBadRequest
from django.middleware.csrf import get_token
import requests
from requests.auth import HTTPBasicAuth
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.utils.dateparse import parse_datetime 

from django.views.decorators.http import require_POST
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone


from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt,ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.conf import settings
from datetime import datetime





# Create your views here.
class Base1CView(View):
    """Base view for all 1C template requests using Basic Auth for the Administrator."""
    admin_login = os.getenv('ONE_C_ADMIN_LOGIN')
    admin_password = os.getenv('ONE_C_ADMIN_PASSWORD')
    one_c_path = os.getenv('ONE_C_PATH')
    one_c_server_url = os.getenv('ONE_C_SERVER_URL')

    def _prepare_headers(self, request):
        """Prepare authentication headers for the Administrator user."""
        
        """token = request.session.get("1c_token")
        if not token:
            # Token is missing, which means the user is not authenticated.
            # Handle this gracefully (e.g., redirect to login).
            print("Missing 1C token, redirecting to login.")
            return HttpResponseRedirect(reverse('login_view')) """

        userpass = f"{self.admin_login}:{self.admin_password}".encode("utf-8")
        basic_auth = base64.b64encode(userpass).decode("ascii")
        return {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/json"
        }

    def _call_1c_endpoint(self, request, method, address_path, additional_params=None):
        """Generic 1C API caller using Basic Auth."""
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
                headers=self._prepare_headers(request)
            )
            
            if response.status_code == 200:
                # Process the response from 1C
                response_from_1c = response.json()
                typOfresponse = response_from_1c.get('ТипОтвета', 'html')
                text_response = response_from_1c.get('ТекстСтраницы', '')
                content_type = "text/html" if typOfresponse == 'html' else "application/json"
                
                if content_type == "application/json":
                    return JsonResponse(response_from_1c, safe=False)
                else:
                    return HttpResponse(text_response, content_type=content_type)
            else:
                error_message = (f"Ошибка получения шаблона из 1С: "
                                 f"код {response.status_code}, Ответ: {response.text}")
                return HttpResponse(error_message, 
                                    status=response.status_code, 
                                    content_type="text/plain")
        except requests.exceptions.RequestException as e:
            error_message = f"Ошибка сети при подключении к 1С: {e}"
            return HttpResponse(error_message, 
                                status=500, 
                                content_type="text/plain")
 
class RequestSenderTo1C(Base1CView):
    """Handles main page template requests"""
    def get(self, request):
        token = request.session.get('1c_token')
        
        # If the token is missing, redirect the user to the login page
        if not token:
            print("Missing 1C token, redirecting to login.")
            return redirect(reverse('login_view'))
        
        typeOfRequest = request.GET.get('typeOfRequest', 'document_list')
        print(f"Type of request: {typeOfRequest}")
        request_params_to_send = {
           "ТелоЗапроса":{ "typeOfRequest": typeOfRequest,
                          "user": request.user.username,
                          "token": token,
                          "timestamp": timezone.now().isoformat(),
                           **{key: value for key, value in request.GET.items()},
            }
        }
        address_path = f"http://localhost/{self.one_c_path}/hs/MobileExchange/request_handler/"
        return self._call_1c_endpoint(request,"POST", address_path=address_path, additional_params=request_params_to_send) 
               
    def post(self, request):
        token = request.session.get('1c_token')
        
        # If the token is missing, redirect the user to the login page
        if not token:
            print("Missing 1C token, redirecting to login.")
            return redirect(reverse('login_view'))
        
        request_data = {}
        content_type = request.META.get('CONTENT_TYPE', '').lower()

        if 'application/json' in content_type:
            # Handle JSON body
            try:
                request_data = json.loads(request.body.decode('utf-8'))
                print("Received JSON payload.")
            except json.JSONDecodeError:
                return HttpResponse("Invalid JSON in request body.", status=400, content_type="text/plain")
        elif 'multipart/form-data' in content_type or 'application/x-www-form-urlencoded' in content_type:
            # Handle form data (request.POST) and files (request.FILES)
            print("Received form-data or url-encoded payload.")
            # Text fields from request.POST
            for key, value in request.POST.items():
                # If a key exists in request_data from a potential earlier JSON parse,
                # you need a strategy (e.g., prioritize form data, merge, etc.).
                # For now, we'll assume they are mutually exclusive or form data overrides.
                request_data[key] = value

            # Handle files from request.FILES (only relevant for multipart/form-data)
            files_to_send_to_1c = []
            if request.FILES:
                print(f"Received {len(request.FILES)} file(s).")
                for file_name, uploaded_file in request.FILES.items():
                    try:
                        file_content_binary = uploaded_file.read()
                        base64_encoded_content = base64.b64encode(file_content_binary).decode('utf-8')

                        files_to_send_to_1c.append({
                            "ИмяФайла": uploaded_file.name,
                            "ТипКонтента": uploaded_file.content_type,
                            "Размер": uploaded_file.size,
                            "Данные": base64_encoded_content
                        })
                    except Exception as e:
                        print(f"Error processing file '{uploaded_file.name}': {e}")
                        return HttpResponse(f"Error processing file: {uploaded_file.name}", status=500)
            
            request_data['files'] = files_to_send_to_1c
        else:
            # Fallback for unhandled content types, or if no data is found
            # You could also consider request.body for other raw content types
            print(f"Unhandled Content-Type: {content_type} or no data found. Falling back to empty request_data.")
            # If you want to allow empty POST/FILES to mean no data, leave request_data as {}


        # Construct the final payload for 1C
        request_params_to_send = {
            "ТелоЗапроса": request_data,
            "token": token,
            "timestamp": timezone.now().isoformat(),
        }

        address_path = f"http://localhost/{self.one_c_path}/hs/MobileExchange/request_handler/"
        
        #print(f"Handling POST request with data: {request_params_to_send}")
        return self._call_1c_endpoint(request,"POST", address_path=address_path, additional_params=request_params_to_send)
   

class DocumentDetail1CView(Base1CView):
    """Handles document detail template requests"""
    def get(self, request, guid):
        address_path= f"http://localhost/{self.one_c_path}/hs/MobileExchange/document_detail/{guid}/"
        #print(f"Address path for document detail: {address_path}")
        return self._call_1c_endpoint("GET",address_path=address_path, additional_params={
            "guid": guid
        })
        
class MainPage1CView(Base1CView):
    """Handles main page template requests"""
    def get(self, request):
        address_path = f"http://localhost/{self.one_c_path}/hs/MobileExchange/main_page/"
        return self._call_1c_endpoint("POST", address_path=address_path)        
        
        
def test_view(request):
    print("=== TEST VIEW HIT ===")
    return HttpResponse("Simple test works")



@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    def get(self, request):
        print("=== GET LOGIN VIEW ===")
        base_view = Base1CView()
        address_path = f"http://localhost/{base_view.one_c_path}/hs/MobileExchange/request_handler/"
        payload = {
            "ТелоЗапроса": {
                "typeOfRequest": "get_login_template"
            }
        }
        
        # This function already returns a Django HttpResponse
        http_response_from_1c = base_view._call_1c_endpoint(request, "POST", address_path=address_path, additional_params=payload)
        
        # Now, check the status code of the HttpResponse
        if http_response_from_1c and http_response_from_1c.status_code == 200:
            try:
                html_content_string = http_response_from_1c.content.decode('utf-8')
            
                # Get Django messages from the session
                django_messages = list(messages.get_messages(request))
                error_message_html = ""
                if django_messages:
                    # We'll assume the error message is the first one
                    error_message = django_messages[0]
                    error_message_html = f'<div class="error-message">{error_message}</div>'
                
                # Replace a placeholder in the HTML from 1C with the error message
                # Your 1C template must have a placeholder like ''
                html_content_string = html_content_string.replace('[error_message]', error_message_html)
            
                # Inject CSRF token as you planned
                csrf_token_value = get_token(request)
                html_content_string = html_content_string.replace("{% csrf_token %}", f'<input type="hidden" name="csrfmiddlewaretoken" value="{csrf_token_value}">')
            
                return HttpResponse(html_content_string, content_type="text/html")
        
            except json.JSONDecodeError:
                # If the 1C response is not JSON, it might be the raw HTML or an error page.
                # In this case, you can return the HttpResponse directly.
               
                return http_response_from_1c
        
        # If the request to 1C failed
        error_message = (f"Failed to retrieve login page from 1C. "
                         f"Status: {http_response_from_1c.status_code if http_response_from_1c else 'N/A'}")
        return HttpResponse(error_message, status=500)
    
    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        #print(f"Attempting to authenticate user: {user}")
        с_token = request.session.get('1c_token')
        #print("1с token:", request.session.get('1c_token'))
        
        if user is not None:
            login(request, user)
            request.session['1c_token'] = с_token
            #print("1с token:", request.session.get('1c_token'))
            # Redirect to the main page after successful login
            return redirect(reverse('request_sender_to_1c'))
        else:
            messages.error(request, 'Invalid username or password.')
            #print("Invalid login attempt")
            return redirect(reverse('login_view'))
    
    # You will no longer use a login.html template. The HTML comes from 1C.
    # The render() call is removed from the GET branch.



@method_decorator(ensure_csrf_cookie, name='dispatch')
class ProxyView(View):
    """
    A Django proxy view to handle requests to the 1C backend, bypassing CORS issues.
    It handles GET, POST and OPTIONS requests.
    """
    
    # The target URL of the 1C service from your settings.py
    #target_url = settings.ONE_C_TARGET_URL
    target_url = "https://1c-dev.kazuni.kz/Ag_Tech_Web/hs/MobileExchange/redirection" 

    def dispatch(self, request, *args, **kwargs):
        """
        Overridden to handle the OPTIONS method for CORS preflight.
        """
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Authorization, X-CSRFToken'
            response['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        return super().dispatch(request, *args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        """
        Handles GET requests to provide CSRF token and server info.
        The @ensure_csrf_cookie decorator ensures the CSRF cookie is set.
        """
        # Get the CSRF token for this request
        csrf_token = get_token(request)
        
        response_data = {
            'message': 'Django proxy server for 1C backend',
            'csrf_token': csrf_token,
            'timestamp': datetime.now().isoformat(),
            'target_url': self.target_url,
            'methods_allowed': ['GET', 'POST', 'OPTIONS'],
            'endpoints': {
                'csrf_token': 'GET /api/ - Get CSRF token',
                'proxy': 'POST /api/ - Proxy to 1C backend'
            }
        }
        
        response = JsonResponse(response_data)
        # Add CORS headers to GET response
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Credentials'] = 'true'
        return response

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests by forwarding them to the 1C backend.
        """
        # Log the incoming request for debugging
        #print(f"POST request received at /api/")
        #print(f"Request headers: {dict(request.headers)}")
        #print(f"Request body: {request.body}")
        #print(f"CSRF token from header: {request.headers.get('X-CSRFToken', 'Not found')}")
        
        # Copy headers from the incoming request.
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in ['host', 'cookie', 'x-csrftoken'] # Exclude headers that can cause issues
        }
        
        # Ensure Content-Type is set for JSON
        headers['Content-Type'] = 'application/json'

        try:
            # Load the request body as JSON
            request_body = json.loads(request.body)
            
            #print(f"Parsed request body: {request_body}")
            #print(self.target_url)
            #print(f"Forwarding to 1C with headers: {headers}")
            
            # Forward the request to the 1C backend
            backend_response = requests.post(
                self.target_url,
                json=request_body,
                headers=headers,
                timeout=30 # Set a timeout to avoid hanging
            )
            
            #print(f"1C Response status: {backend_response.status_code}")
            #print(f"1C Response body: {backend_response.text}")
            
            # Return the response from the 1C backend to the client
            try:
                response_data = backend_response.json()
            except json.JSONDecodeError:
                response_data = {
                    'error': 'Invalid JSON from 1C backend',
                    'response_text': backend_response.text,
                    'status_code': backend_response.status_code
                }
            
            proxy_response = JsonResponse(response_data, safe=False, status=backend_response.status_code)
            
            # Add CORS headers to POST response
            proxy_response['Access-Control-Allow-Origin'] = '*'
            proxy_response['Access-Control-Allow-Credentials'] = 'true'
            
            return proxy_response

        except json.JSONDecodeError as e:
            #print(f"JSON decode error: {str(e)}")
            #print(f"Raw request body: {request.body}")
            return HttpResponseBadRequest(f"Invalid JSON in request body: {str(e)}")
        except requests.exceptions.Timeout:
            return JsonResponse({
                "error": "Gateway Timeout",
                "message": "The proxy could not connect to the 1C backend in time."
            }, status=504)
        except requests.exceptions.RequestException as e:
            #print(f"Request exception: {str(e)}")
            return JsonResponse({
                "error": "Proxy Error",
                "message": str(e)
            }, status=500)
        except Exception as e:
            #print(f"Unexpected error: {str(e)}")
            return JsonResponse({
                "error": "Internal Server Error",
                "message": str(e)
            }, status=500)