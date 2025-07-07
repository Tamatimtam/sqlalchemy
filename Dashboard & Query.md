### **REVISED LAMIS v2, Mission 2: Actually Seeing Things**

Our goal is to create the "Recent Activity" feed from the dashboard screenshot. We will fetch live alert data from Wazuh and display it in a simple list. This revised guide includes all necessary configuration steps and uses clean code blocks.

---

### **Step 1. Configuration: Preparing for the API Call**

Before we can ask our "butler" to fetch data, we need to give him the keys to the library. This means telling our Flask app the address of the Wazuh API and the credentials to use. We do this securely using environment variables.

> **Action 1: Update your `.env` file**
>
> In the root of your `LoginWTF` project, open or create the `.env` file. Add the following lines, replacing the placeholder values with your actual Wazuh instance details. The Wazuh API typically runs on port 9200.

```dotenv
# .env

# ... keep your existing SECRET_KEY and DATABASE_URL ...

# --- ADD THESE WAZUH VARIABLES ---
WAZUH_URL=https://YOUR_WAZUH_SERVER_IP:9200
WAZUH_USER=admin
WAZUH_PASS=YourWazuhAdminPassword
```

> **Action 2: Update `config.py`**
>
> Now, we need to instruct our Flask application to load these new variables from the `.env` file into its configuration.

**Open `LoginWTF/config.py` and add the three new lines for Wazuh:**

```python
# LoginWTF/config.py
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- ADD THESE THREE LINES ---
    WAZUH_URL = os.environ.get("WAZUH_URL")
    WAZUH_USER = os.environ.get("WAZUH_USER")
    WAZUH_PASS = os.environ.get("WAZUH_PASS")
```

With this complete, our app now knows how to connect to Wazuh.

---

### **Step 2. The Butler: Creating the Service Layer**

We will not put the API call logic directly in our route. Instead, we create a "service" function to handle this chore. This keeps our code organized, reusable, and easy to test.

> **Action: Create `app/dashboard/services.py`**
>
> This file will contain our "butler" function, `get_wazuh_alerts`, which is solely responsible for fetching data from Wazuh.

```python
# app/dashboard/services.py
import requests
from flask import current_app

def get_wazuh_alerts(limit: int = 20):
    """
    Fetches the latest alerts from the Wazuh Indexer.
    This is our "butler" function. It does the dirty work of talking to the API.
    """
    # 'current_app' is a special Flask object that points to the currently running app.
    # We use it to safely access our app's configuration (like the Wazuh URL and password).
    config = current_app.config

    # This is the specific API endpoint for searching alerts in Wazuh.
    # The '*' is a wildcard, meaning "search across all daily alert indices".
    wazuh_url = f"{config['WAZUH_URL']}/wazuh-alerts-*/_search"

    # This is our Query DSL. It's a Python dictionary that we'll convert to JSON.
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }

    try:
        with requests.Session() as session:
            # Set the username and password for the request.
            session.auth = (config["WAZUH_USER"], config["WAZUH_PASS"])

            # For a local sandbox, `verify=False` is fine to bypass self-signed cert errors.
            response = session.post(wazuh_url, json=query, verify=False, timeout=10)
            
            # If the API returned an error (e.g., 401 Unauthorized), this will raise an exception.
            response.raise_for_status()
            
            data = response.json()

            # The actual list of alerts is nested. We use .get() to safely access keys
            # and return an empty list if any part of the path is missing.
            return data.get("hits", {}).get("hits", [])
            
    except requests.exceptions.RequestException as e:
        # If the web request fails for any reason, log the error and return an empty list.
        # This prevents the entire page from crashing.
        current_app.logger.error(f"Failed to fetch alerts from Wazuh: {e}")
        return []
```

---

### **Step 3. The Phone Call: Making the Route Use the Service**

Now our route simply needs to "call the butler" and hand off the results to the template.

> **Action: Modify `app/dashboard/routes.py`**
>
> We will import our new `get_wazuh_alerts` function and call it from the `index` route.

```python
# app/dashboard/routes.py
from flask import render_template, Blueprint
from flask_login import login_required
# Import our new butler function!
from app.dashboard.services import get_wazuh_alerts

bp = Blueprint("dashboard", __name__)

@bp.route("/")
@login_required
def index():
    # The route asks the service for the latest alerts. It doesn't know or care how they are fetched.
    latest_alerts = get_wazuh_alerts()
    
    # We pass the list of alerts into our HTML template under the variable name 'alerts'.
    return render_template("dashboard/index.html", alerts=latest_alerts)
```

---

### **Step 4. The Payoff: Displaying the Data**

This is where we build the front-end to display the data we've fetched.

> **Action 1: Create the Base Layout**
>
> A base layout prevents us from repeating the same HTML `<head>` section on every page.

**Create the folder `app/templates/layouts` and add the file `base.html`:**

```html
<!-- app/templates/layouts/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

> **Action 2: Fix the Stylesheet Path and Create the CSS File**
>
> Your `base.html` links to `css/style.css`. Let's make sure the directory structure matches.

**Rename the folder `app/static/styles` to `app/static/css`.** Then, ensure the file `app/static/css/style.css` exists with the following content:

```css
/* app/static/css/style.css */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: #121212;
    color: #e0e0e0;
    line-height: 1.6;
}
.container {
    max-width: 900px;
    margin: 40px auto;
    padding: 20px;
}
h1, h2 {
    color: #ffffff;
    border-bottom: 1px solid #333;
    padding-bottom: 10px;
}
.activity-feed {
    background-color: #1e1e1e;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
}
.activity-item {
    padding: 15px;
    border-bottom: 1px solid #333;
}
.activity-item:last-child {
    border-bottom: none;
}
.item-header {
    font-weight: bold;
    color: #ffffff;
}
.item-meta {
    font-size: 0.85em;
    color: #888;
}
.item-meta span {
    margin-right: 15px;
}
```

> **Action 3: Create the Dashboard Template**
>
> Finally, we'll overhaul the dashboard's HTML to display the list of alerts. In this template:
> *   `{% extends "layouts/base.html" %}` tells Jinja to use our base file as a wrapper.
> *   `{% if alerts %}` checks if the `alerts` list we passed from the route is not empty.
> *   `{% for alert in alerts %}` loops through each item in the list.
> *   The data from Wazuh is a nested JSON object. We access values like a Python dictionary (e.g., `alert._source.rule.description`). We also check if keys like `srcip` exist before trying to access them to avoid errors.

**Replace the content of `app/templates/dashboard/index.html` with this clean version:**

```html
{% extends "layouts/base.html" %}

{% block content %}
    <h1>LAMIS Dashboard</h1>
    <p>Welcome back! <a href="{{ url_for('auth.logout') }}">Sign Out</a></p>

    <div class="activity-feed">
        <h2>Recent Activity</h2>
        
        {% if alerts %}
            {% for alert in alerts %}
                <div class="activity-item">
                    <div class="item-header">{{ alert._source.rule.description }}</div>
                    <div class="item-meta">
                        <span>Timestamp: {{ alert._source.timestamp }}</span>
                        <span>Source IP: {{ alert._source.data.srcip if alert._source.data and 'srcip' in alert._source.data else 'N/A' }}</span>
                        <span>Level: {{ alert._source.rule.level }}</span>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <p>Could not fetch alerts from Wazuh, or there are no recent alerts.</p>
        {% endif %}
    </div>
{% endblock %}
```

---

### **Launch It!**

Your code should now be fully functional.

1.  Make sure your PostgreSQL and Wazuh containers are running.
2.  Ensure your `.env` file is complete and saved.
3.  Activate your Python virtual environment (`source .venv/bin/activate`).
4.  Run the app from your project root (`LoginWTF/`):
    ```bash
    flask run
    ```
5.  Log in.

You should now see the "LAMIS Dashboard" with a dark theme, displaying a "Recent Activity" box filled with the latest 20 alerts from your Wazuh instance. This complete workflow is the core of web application development. Well done.
