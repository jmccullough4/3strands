## 3 Strands Cattle Co. Dashboard

### Local sign-in

The dashboard ships with a local authentication flow. On first run an administrator account is created with the credentials `admin` / `ChangeMe123!`. Sign in with that account and visit **Manage users** to add ranch teammates, fill in their contact details, and set temporary passwords (minimum eight characters).

Encourage teammates to change their password after the first login via the avatar menu ➝ **Change password**.

### Running locally

```bash
python3 app.py
```

The server listens on port `8081` by default. Uploads are stored in the `uploads/` directory next to `app.py`, and the SQLite database lives under `instance/dashboard.db`.

### Updating the calendars

By default the dashboard surfaces the ranch-wide Google Calendar at `c_5545ea209f164c2ff801f63851bf358a7f85b6115d1162e8a4bcb8db84f391dd@group.calendar.google.com`. If you prefer a different calendar (or multiple calendars), override the `CALENDAR_EMBEDS` list in `instance/config.py` or set the `GOOGLE_CALENDAR_PRIMARY` environment variable.
