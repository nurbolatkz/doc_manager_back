# HTTPS/SSL Configuration Guide

## 1. Obtain SSL Certificate

### Option A: Using Let's Encrypt (Free)
1. Install Certbot:
```bash
# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx  # for Nginx
# OR
sudo apt-get install certbot python3-certbot-apache # for Apache
```

2. Get SSL Certificate:
```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
# OR for Apache
sudo certbot --apache -d your-domain.com -d www.your-domain.com
```

### Option B: Using Commercial SSL (Paid)
1. Purchase SSL certificate from provider (e.g., DigiCert, Comodo, etc.)
2. Generate CSR (Certificate Signing Request)
3. Install the certificate files provided by your SSL provider

## 2. Nginx Configuration (if using Nginx)

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;  # Redirect HTTP to HTTPS
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;

    location /static/ {
        alias /path/to/your/staticfiles/;
    }

    location /media/ {
        alias /path/to/your/media/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;  # Your Django app
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 3. Apache Configuration (if using Apache)

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    ServerAlias www.your-domain.com
    Redirect permanent / https://your-domain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName your-domain.com
    ServerAlias www.your-domain.com

    SSLEngine on
    SSLCertificateFile /path/to/your/certificate.crt
    SSLCertificateKeyFile /path/to/your/private.key
    SSLCertificateChainFile /path/to/your/chain.crt

    # SSL Configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off

    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000"

    Alias /static/ /path/to/your/staticfiles/
    Alias /media/ /path/to/your/media/

    <Directory /path/to/your/staticfiles/>
        Require all granted
    </Directory>

    <Directory /path/to/your/media/>
        Require all granted
    </Directory>

    WSGIDaemonProcess dms_core python-path=/path/to/your/virtualenv/lib/python3.x/site-packages
    WSGIProcessGroup dms_core
    WSGIScriptAlias / /path/to/your/dms_core/dms_core/wsgi.py

    <Directory /path/to/your/dms_core/dms_core>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>
</VirtualHost>
```

## 4. Django Settings Update

Ensure your Django settings.py has these settings (already configured in your settings.py):

```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

## 5. Test SSL Configuration

1. Use SSL Labs Server Test:
   - Visit https://www.ssllabs.com/ssltest/
   - Enter your domain name
   - Wait for the test to complete
   - Aim for A+ rating

2. Test HTTPS Locally:
```bash
# Test Nginx config
sudo nginx -t

# Test Apache config
sudo apache2ctl configtest
```

## 6. Maintenance

1. Set up auto-renewal for Let's Encrypt certificates:
```bash
# Add to crontab
sudo crontab -e

# Add this line to run twice daily
0 0,12 * * * certbot renew --quiet
```

2. Monitor SSL certificate expiration
3. Regularly check SSL Labs grade
4. Keep web server and SSL libraries updated

## 7. Troubleshooting

Common issues and solutions:

1. Mixed Content Warnings:
   - Check for hard-coded HTTP URLs in your templates
   - Update any external resources to use HTTPS
   - Use relative URLs where possible

2. Certificate Issues:
   - Verify certificate chain is complete
   - Check certificate permissions
   - Ensure private key matches certificate

3. Performance Issues:
   - Enable HTTP/2
   - Configure proper SSL session caching
   - Use OCSP stapling

For any issues:
1. Check web server error logs
2. Verify SSL certificate validity
3. Test SSL configuration using SSL Labs
4. Review security headers using https://securityheaders.com
