# Production Deployment Checklist

## Environment Setup
1. Create and configure .env file with proper values:
   - Set DEBUG=False
   - Set a strong SECRET_KEY
   - Configure ALLOWED_HOSTS with your domain(s)
   - Set proper ONE_C credentials and URLs

## Security
1. Enable HTTPS/SSL
2. Configure your web server (e.g., Nginx, Apache) with proper security headers
3. Set up proper firewall rules
4. Review and restrict access to admin interface

## Static Files
1. Run `python manage.py collectstatic`
2. Configure web server to serve static files
3. Set up media files serving configuration

## Database
1. Use a production-grade database (e.g., PostgreSQL)
2. Configure database backup strategy
3. Set up proper database user permissions

## Monitoring
1. Set up error logging
2. Configure monitoring for server resources
3. Set up backup monitoring

## Performance
1. Enable caching
2. Configure compression for static files
3. Set up CDN if needed

## Before Going Live
1. Test all forms and functionality
2. Verify all environment variables are properly set
3. Check all 1C integration points
4. Test backup and restore procedures
5. Run security scan
6. Update all packages to latest stable versions
