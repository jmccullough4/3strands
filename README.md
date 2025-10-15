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

The shared Google Calendar embeds on the dashboard pull from the `CALENDAR_EMBEDS` configuration in `app.py` (or `instance/config.py`). Replace the placeholder URLs with the calendars you want to surface to the team.
