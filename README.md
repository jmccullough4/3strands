## 3 Strands Cattle Co. Dashboard

### Google Workspace single sign-on

Set the following environment variables before running the Flask app so team members can sign in with their corporate accounts:

```
export GOOGLE_CLIENT_ID="<OAuth client ID>"
export GOOGLE_CLIENT_SECRET="<OAuth client secret>"
export GOOGLE_APPS_DOMAIN="3strands.co"
```

Only addresses that the admin authorizes inside the Access Control panel will be able to authenticate.
