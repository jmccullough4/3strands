## 3 Strands Cattle Co. Dashboard

### Google Workspace single sign-on

Provide your Google OAuth client credentials either by exporting environment variables **or** by creating an `instance/config.py` file next to `dashboard.db` with values such as:

```python
GOOGLE_CLIENT_ID = "<OAuth client ID>"
GOOGLE_CLIENT_SECRET = "<OAuth client secret>"
# Optional: supply a hosted URL if it differs from the default http://dashboard.3strands.co:8081
EXTERNAL_BASE_URL = "https://dashboard.3strands.co"
# Optional: hint Google to prefer a Workspace domain (leave blank to allow any Google account)
GOOGLE_APPS_DOMAIN = ""
```

Only addresses that the admin authorizes inside the Access Control panel will be able to authenticate, even if the Google account belongs to another domain.

> **Note:** Google still requires redirect URIs to match the origins configured for your OAuth client and may block callbacks that use private IP addresses. For production deployments, secure the dashboard with HTTPS and register that public URL in Google Cloud. The application allows `http://` redirects for public hostnames so you can prototype without manually setting flags, but Google may enforce HTTPS depending on your project settings.
