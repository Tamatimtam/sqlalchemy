### **LAMIS v2, Mission 2: Actually Seeing Things**

Our goal is to create the "Recent Activity" feed from the dashboard screenshot. We will fetch live alert data from Wazuh and display it in a simple list. That's it.

<details>
<summary><b>Step 1. The Enemy: What the Heck is a "Wazuh Indexer"?</b></summary>

Before we can query something, we have to know what it is.

The **Wazuh Indexer** is basically a giant, hyper-organized library for all our security alerts. Every time Wazuh detects something, it writes a "book" (an alert) and sends it to this library. The library's real name is **OpenSearch** (which is a clone of another tool called Elasticsearch).

You don't need to be an expert on it, but you need to know these three things:
1.  It stores data in a format called **JSON**.
2.  It's incredibly fast at searching through millions of alerts.
3.  We talk to it using a **REST API**, which just means we send it web requests, like our browser does.

> **🤔 Jargon Buster: Query DSL (Domain Specific Language)**
> How do we ask the library for a specific book? We can't just send it a text message. We have to speak its language. That language is called **Query DSL**.
>
> It looks like a complicated JSON object, and honestly, it is. It's fussy and annoying. But it's also incredibly powerful. It's how you tell the indexer, "Hey, give me the 20 most recent alerts, where the rule level is higher than 10, and the source IP is from North Korea."
>
> For today, our query will be simple: "Just give me the latest stuff you've got."

</details>

<details>
<summary><b>Step 2. 🤵 The Butler: Creating a Service Layer</b></summary>

We *could* just put the code to call the Wazuh API directly in our `routes.py` file. **We will not do this.** That's how you make spaghetti code.

Instead, we create a **Service Layer**. Think of it this way:
*   The **Route** (`routes.py`) is the master of the house. It's busy dealing with web requests. It doesn't have time for chores.
*   The **Service** (`services.py`) is the butler. The master simply says, "Jeeves, fetch me the latest alerts." The butler knows exactly which library to go to, how to ask for the books, and how to bring them back on a silver platter.

> **🤔 Why We Do This (The "Why" of Service Layers):**
> 1.  **Reusability:** What if another part of our app also needs alerts? We can just call the butler again. We don't have to copy-paste the code.
> 2.  **Readability:** Our route file stays clean and simple. Its only job is to handle the web request and call the right service.
> 3.  **Testability:** It's way easier to test our "butler" function in isolation than to test a whole web request.

Let's create the butler.

**Create a new file: `app/dashboard/services.py`**

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
        # "size": How many results do we want back?
        "size": limit,
        # "sort": How should the results be ordered?
        "sort": [
            # We want to sort by the 'timestamp' field...
            { "timestamp": { "order": "desc" }} # ...in descending order (newest first).
        ],
        # "query": What are we searching for?
        "query": {
            # "match_all": {} is the simplest query. It means "give me everything".
            "match_all": {}
        }
    }

    try:
        # Using a 'requests.Session' is slightly more efficient than calling 'requests.post' directly,
        # especially if we make multiple calls.
        with requests.Session() as session:
            # Set the username and password for the request.
            session.auth = (config['WAZUH_USER'], config['WAZUH_PASS'])

            # In a real production environment, you'd provide a path to a certificate file.
            # For our local sandbox, `verify=False` is fine. It just tells it not to complain
            # about the self-signed certificate Wazuh generates by default.
            response = session.post(wazuh_url, json=query, verify=False, timeout=10)
            
            # This is a super helpful line. If the API returned an error (like 401 Unauthorized
            # or 500 Server Error), this will immediately raise an exception and we'll jump
            # to the 'except' block below.
            response.raise_for_status()
            
            data = response.json()

            # The actual list of alerts is buried deep in the JSON response.
            # We use .get() with a default value (like {} or []) to avoid crashing if a key
            # doesn't exist. This is called "defensive programming".
            # It's saying "try to get 'hits', if not, give me an empty dict. From that,
            # try to get 'hits' again, if not, give me an empty list."
            return data.get('hits', {}).get('hits', [])
            
    except requests.exceptions.RequestException as e:
        # If anything goes wrong with the web request (network down, wrong URL, auth failed),
        # we catch the error here.
        current_app.logger.error(f"Failed to fetch alerts from Wazuh: {e}")
        # We return an empty list so the rest of the app doesn't crash. The page will
        # just show "No alerts found," which is better than a 500 error page.
        return []

```

</details>

<details>
<summary><b>Step 3. 📞 The Phone Call: Making the Route Use the Service</b></summary>

Now that our butler is ready, we just need to make the phone call from our dashboard route.

**Open `app/dashboard/routes.py` and modify it:**

```python
# app/dashboard/routes.py
from flask import render_template, Blueprint
from flask_login import login_required
# Import our new butler function!
from app.dashboard.services import get_wazuh_alerts

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@login_required
def index():
    # Look how clean this is! The route doesn't know or care HOW we get the alerts.
    # It just asks the service and gets a list back.
    latest_alerts = get_wazuh_alerts()
    
    # We then pass this list into our HTML template.
    # The name 'alerts' on the left is the variable name we'll use in the HTML.
    # The 'latest_alerts' on the right is our Python variable holding the data.
    return render_template('dashboard/index.html', alerts=latest_alerts)
```

</details>

<details>
<summary><b>Step 4. 🎨 The Payoff: Displaying the Data with Jinja2</b></summary>

We have the data in our backend. Now we need to make it show up on the page. This is where Jinja2 comes in.

**1. The Base Layout (So We Don't Repeat Ourselves):**
It's annoying to copy and paste the `<head>` section into every single HTML file. Let's create a master layout.

**Create a new folder `app/templates/layouts` and a new file `app/templates/layouts/base.html`:**

```html
<!-- app/templates/layouts/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS Dashboard</title>
    <!-- We'll add a link to a new CSS file here -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container">
        <!-- This is a placeholder. Any template that "extends" this file can
             fill in this block with its own unique content. -->
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

**2. The New Stylesheet:**
Let's add some basic styling to make it look less like a 1998 website.

**Create a new folder `app/static/css` and a new file `app/static/css/style.css`:**

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

**3. The Dashboard Template (`app/templates/dashboard/index.html`):**
Now, let's completely overhaul our dashboard's HTML to display the list of alerts.

**Replace the content of `app/templates/dashboard/index.html` with this:**

```html
<!-- app/templates/dashboard/index.html -->

<!-- This tells Jinja to use our base.html file as a wrapper. -->
{% extends "layouts/base.html" %}

<!-- This content will be injected into the {% block content %} of the base file. -->
{% block content %}
    <h1>LAMIS Dashboard</h1>
    <p>Welcome back! <a href="{{ url_for('auth.logout') }}">Sign Out</a></p>

    <div class="activity-feed">
        <h2>Recent Activity</h2>
        
        <!-- Here's the logic. If the 'alerts' list we passed from the route is not empty... -->
        {% if alerts %}
            <!-- ...then we loop through each 'alert' in the list. -->
            {% for alert in alerts %}
                <div class="activity-item">
                    <!-- 
                        This is the part that confuses everyone at first.
                        The data from Wazuh is a nested JSON object. To get the rule description,
                        the path is alert -> _source -> rule -> description.
                        We access it just like a Python dictionary.
                    -->
                    <div class="item-header">{{ alert._source.rule.description }}</div>
                    <div class="item-meta">
                        <span>Timestamp: {{ alert._source.timestamp }}</span>
                        <!-- 
                            Not every alert has a source IP. If we just did alert._source.data.srcip,
                            the page would crash if 'data' or 'srcip' didn't exist.
                            This is a safe way to check and provide a fallback.
                        -->
                        <span>Source IP: {{ alert._source.data.srcip if alert._source.data and 'srcip' in alert._source.data else 'N/A' }}</span>
                        <span>Level: {{ alert._source.rule.level }}</span>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <!-- If the 'alerts' list was empty, we show this message instead. -->
            <p>Could not fetch alerts from Wazuh, or there are no recent alerts.</p>
        {% endif %}
    </div>
{% endblock %}
```

**4. The Final Piece: Update `run.py`**
We need to make one tiny change to `run.py` to tell it where to find our Blueprints correctly.

```python
# run.py
from app import create_app

# The app context is needed for the 'flask' command line tool
# and for the app to properly initialize.
app = create_app()

if __name__ == '__main__':
    # debug=True is great for development. It auto-reloads the server when you
    # save a file and gives you a nice interactive debugger if something crashes.
    # NEVER run with debug=True in production.
    app.run(host='0.0.0.0', port=5000, debug=True)
```
Also, update `app/__init__.py` to import `config.py` correctly from the root.

```python
# In app/__init__.py, change:
from config import Config
# To:
import sys
import os
# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
```
*Correction*: A better way is to not modify `sys.path`. Let's adjust the structure slightly to make imports cleaner. The `run.py` at the root handles this. My previous `__init__.py` was fine. Let's revert that `sys.path` change. The key is running `flask run` from the root directory where `run.py` is, so Python's import system works correctly.

Final `app/__init__.py` for clarity:
```python
# app/__init__.py
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config
from app.models import db
from app.models.user import User
from app.models.state import InitializationState

# ... rest of the file from Step 4 ...
```
The original structure was correct. My apologies for the momentary confusion. The key is that `run.py` imports `create_app` from the `app` package.

</details>

### **Launch It!**

Let's see our work.
1.  Make sure your PostgreSQL and Wazuh containers are running.
2.  Make sure your `.env` file is filled out with your Wazuh credentials.
3.  Activate your `venv`.
4.  Run the app: `flask run`.
5.  Log in.

You should now see the "LAMIS Dashboard" page with a dark background and a "Recent Activity" box filled with the 20 latest alerts from your Wazuh instance.

You've just completed the entire round trip: you requested a page, the route was called, it used a service to fetch external data, and then it passed that data to a template to be displayed securely to the user. This is the fundamental pattern of almost every web application you will ever build.

Good work. Now go get some coffee. You've earned it.