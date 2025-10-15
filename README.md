## 3 Strands Cattle Co. Dashboard

### Google Workspace single sign-on

Set the following environment variables before running the Flask app so team members can sign in with their corporate accounts:

```
export GOOGLE_CLIENT_ID="<OAuth client ID>"
export GOOGLE_CLIENT_SECRET="<OAuth client secret>"
export GOOGLE_APPS_DOMAIN="3strands.co"
export EXTERNAL_BASE_URL="https://dashboard.3strands.co"  # public HTTPS URL configured in Google Cloud
# optional: relax checks only during local prototyping
export ALLOW_INSECURE_GOOGLE_REDIRECTS=0
```

Only addresses that the admin authorizes inside the Access Control panel will be able to authenticate.

> **Note:** Google rejects OAuth callbacks that point to private IPs (for example, `http://192.168.x.x`).
> Set `EXTERNAL_BASE_URL` to a publicly routable **HTTPS** host that you've registered as an authorized redirect URI in your Google Cloud console (e.g., `https://dashboard.3strands.co`).
> The `ALLOW_INSECURE_GOOGLE_REDIRECTS=1` flag skips these checks only for local prototyping; Google may still block callbacks that aren't HTTPS or use private IPs.
