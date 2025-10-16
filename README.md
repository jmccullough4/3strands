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

By default the dashboard surfaces the ranch-wide Google Calendar shared at `https://calendar.google.com/calendar/ical/c_5545ea209f164c2ff801f63851bf358a7f85b6115d1162e8a4bcb8db84f391dd%40group.calendar.google.com/public/basic.ics`. The app automatically converts Google share links that use either the `cid=...` format or a public `.ics` feed into an embeddable view, so you can paste whichever Workspace link you have handy. If you prefer a different calendar (or multiple calendars), override the `CALENDAR_EMBEDS` list in `instance/config.py` or set the `GOOGLE_CALENDAR_PRIMARY` environment variable. You can also change the timezone used for embeds by setting `CALENDAR_TIMEZONE` in the same config file.

### Connecting a Trello board

The shared task board can mirror a Trello workspace so everyone collaborates from the same source of truth. Drop the following values into `instance/config.py` (or export them as environment variables) to enable the live integration:

```python
TRELLO_API_KEY = "your-trello-api-key"
TRELLO_API_TOKEN = "your-trello-api-token"
# optional when `TRELLO_BOARD_URL` is set to a standard Trello link
TRELLO_BOARD_ID = "the-board-id-or-shortlink"
```

You can generate an API key and token from [trello.com/app-key](https://trello.com/app-key). Once configured, cards, list updates, and deletions in the dashboard are performed directly against the Trello board, and every refresh pulls the latest lists and cards. If you omit `TRELLO_BOARD_ID`, the app derives it automatically from the configured `TRELLO_BOARD_URL` when possible.

The dashboard also embeds the shared board so teammates can review it at a glance. By default it points to `https://trello.com/b/WLeHBhSM/3-iii`; override `TRELLO_BOARD_URL` in `instance/config.py` (or via an environment variable of the same name) if you need a different workspace. Without API credentials the embed still renders, but card edits must happen directly inside Trello.
