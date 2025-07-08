---

## The Goal: From a Static List to Interactive Exploration

In the `before` version of our app, the dashboard showed a list of the latest Wazuh alerts. This was a good start, but it was a dead end. You could see a summary, but you couldn't investigate further.

Our objective is to make each alert in that list a clickable link. Clicking an alert will take the user to a new page that displays the **entire, raw JSON data** for that specific alert.

This is a foundational feature. By giving ourselves a way to explore the raw alert data, we empower ourselves to discover all the available fields we can use for future features, like automated blocking, reporting, or deeper analysis.

Let's walk through the required changes, step by step.

---

<details>
<summary><strong>Step 1: The Architectural Foundation — A New 'alerts' Blueprint</strong></summary>

### The "Why"

In the old system, we might have been tempted to just add a new route to the existing `dashboard/routes.py` file. This is a classic mistake that leads to "spaghetti code." The dashboard's responsibility is to show a summary; the responsibility of handling individual alerts is a separate concern.

Following our **🏛️ Structure & Modularity Above All** principle, we will create a completely new module (Blueprint) to handle everything related to individual alerts. This keeps our code organized, testable, and easy to understand.

### The "How"

We create a new directory structure inside the `app` folder:

```plaintext
/app
  └── alerts/
      ├── __init__.py      # Makes 'alerts' a Python package
      ├── routes.py        # Will contain the URL endpoint (the user-facing page)
      └── services.py      # Will contain the business logic (how to fetch the alert)
```

This structure immediately tells any developer, "If you want to work with how individual alerts are handled, look inside the `app/alerts` directory." This is the essence of clean architecture.

</details>

<br>

<details>
<summary><strong>Step 2: The Backend Engine — A Precise and Robust Service Function</strong></summary>

### The "Why"

Our backend needs a function to fetch the data for *one specific alert*. The old `get_wazuh_alerts` function in the dashboard service was designed to fetch a *list* of alerts using a broad `_search` query. For a single alert, we can be much more efficient.

We will create a new service function, `get_wazuh_alert_by_id`, that uses a more precise, performant, and robust method to get exactly the data we need. This adheres to our **⚡ Performance & Efficiency** and **⚙️ Robustness & Reliability** principles.

### The "How"

We create a new file: `app/alerts/services.py`.

```python
# app/alerts/services.py

import json
from typing import Dict, Any, Optional

import requests
from flask import current_app


def get_wazuh_alert_by_id(index_name: str, alert_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetches a single Wazuh alert document by its ID from a specific index.

    This uses the more precise GET /<index>/_doc/<id> endpoint.

    Args:
        index_name: The specific index the alert resides in.
        alert_id: The unique _id of the Wazuh alert document.

    Returns:
        A dictionary containing the full alert document (including metadata),
        or None if the alert is not found or an error occurs.
    """
    config = current_app.config
    # CHANGE: We construct a URL to fetch a single document directly.
    # This is much faster than searching an entire index.
    wazuh_url: str = f"{config['WAZUH_URL']}/{index_name}/_doc/{alert_id}"

    current_app.logger.debug(
        f"Attempting to fetch alert document '{alert_id}' from index '{index_name}'."
    )
    current_app.logger.debug(f"Request URL: {wazuh_url}")

    try:
        with requests.Session() as session:
            session.auth = (config["WAZUH_USER"], config["WAZUH_PASS"])
            response: requests.Response = session.get(
                wazuh_url, verify=False, timeout=10
            )

            current_app.logger.debug(f"Received status code: {response.status_code}")
            # This will automatically raise an error for statuses like 500, 401, 403, etc.
            response.raise_for_status()

            full_document: Dict[str, Any] = response.json()

            if full_document.get("found") is True:
                current_app.logger.info(
                    f"Successfully fetched alert document '{alert_id}'."
                )
                # We return the entire document, which includes the useful
                # metadata like `_index` and `_id`.
                return full_document
            else:
                current_app.logger.warning(
                    f"API reported success, but document '{alert_id}' was not found."
                )
                return None

    except requests.exceptions.HTTPError as http_err:
        # IMPROVEMENT: We now specifically handle a 404 (Not Found) error.
        # This is expected if an alert ID is invalid. We log it as a warning,
        # not a critical error.
        if http_err.response.status_code == 404:
            current_app.logger.warning(
                f"Wazuh alert document with ID '{alert_id}' not found in index '{index_name}'. (404)"
            )
        else:
            # For all other HTTP errors, we log it as a more severe error.
            current_app.logger.error(
                f"HTTP error fetching alert '{alert_id}': {http_err}"
            )
        return None
    except requests.exceptions.RequestException as e:
        # This is a catch-all for network issues, timeouts, etc.
        current_app.logger.error(f"Failed to fetch alert '{alert_id}' from Wazuh: {e}")
        return None


def format_json_for_html(data: Dict[str, Any]) -> str:
    """
    Converts a Python dictionary to a pretty-printed JSON string.
    """
    return json.dumps(data, indent=4, sort_keys=True)
```

**Key Improvements Explained:**

1.  **Precise API Endpoint**: Instead of `wazuh-alerts-*/_search`, we use `{index_name}/_doc/{alert_id}`. This is the difference between asking a librarian to search the entire library for a book by its title versus giving them the exact shelf number and book ID. It's infinitely faster and more efficient.
2.  **Required Arguments**: The function now requires `index_name` and `alert_id`. Wazuh stores alerts in different indices (e.g., `wazuh-alerts-4.x-2024.07.08`). To find an alert, we need both its ID and the index it lives in.
3.  **Robust Error Handling**: We specifically check for `404 Not Found` errors. This is a normal scenario (e.g., a user manually enters a wrong ID). We treat it gracefully by returning `None` instead of crashing. All other errors are logged appropriately.
4.  **Logging**: We've added `current_app.logger` calls. This is crucial for debugging. When something goes wrong, these logs will be our best friend. (We'll enable this in Step 7).

</details>

<br>

<details>
<summary><strong>Step 3: Creating the Web Page — The Route</strong></summary>

### The "Why"

The service function knows *how* to get the data, but it doesn't know *when* to run. The route's job is to connect a URL that the user visits to our service function. It acts as the "controller" in our architecture—it handles the web request, calls the service to do the work, and then decides which template to show the user.

### The "How"

We create the `app/alerts/routes.py` file to define our new page's URL.

```python
# app/alerts/routes.py

from flask import render_template, Blueprint, flash, redirect, url_for
from flask_login import login_required

from app.alerts.services import get_wazuh_alert_by_id, format_json_for_html

# We define a new Blueprint named 'alerts' with a URL prefix.
# All routes in this file will start with '/alert'.
bp = Blueprint("alerts", __name__, url_prefix="/alert")


# This is a dynamic route. The parts in < > are placeholders.
# Flask will capture the values from the URL and pass them to our function.
# e.g., /alert/wazuh-alerts-4.x-2024.01.01/ABCDEFG will call:
# detail(index_name="wazuh-alerts-4.x-2024.01.01", alert_id="ABCDEFG")
@bp.route("/<string:index_name>/<string:alert_id>")
@login_required # Security: Ensures only logged-in users can see this page.
def detail(index_name: str, alert_id: str):
    """
    Displays the full details of a single Wazuh alert from a specific index.
    """
    # 1. Call the service to do the heavy lifting.
    alert_data = get_wazuh_alert_by_id(index_name=index_name, alert_id=alert_id)

    # 2. Handle the case where the alert wasn't found.
    if alert_data is None:
        flash(f"Could not find or load alert with ID: {alert_id}", "danger")
        return redirect(url_for("dashboard.index"))

    # 3. Prepare the data for display.
    pretty_alert_json = format_json_for_html(alert_data)

    # 4. Render the HTML template, passing the data to it.
    return render_template(
        "alerts/alert_detail.html", alert_id=alert_id, alert_json=pretty_alert_json
    )
```

**Key Concepts Explained:**

1.  **Dynamic Routing**: The syntax `<string:variable_name>` tells Flask to expect a value in that part of the URL and to pass it as a string argument to our `detail` function. This is how we get the `index_name` and `alert_id` from the user's browser.
2.  **Thin Route**: Notice how clean this function is. It doesn't know *how* to talk to Wazuh. It just calls the service function. This separation of concerns is critical for maintainability.
3.  **Graceful Failure**: If `get_wazuh_alert_by_id` returns `None`, we don't crash. We use Flask's `flash` to show a user-friendly error message and redirect them safely back to the dashboard.

</details>

<br>

<details>
<summary><strong>Step 4: Displaying the Data — The HTML Template</strong></summary>

### The "Why"

We have the data, now we need to show it to the user. We'll create a new HTML template specifically for the alert detail page. This follows our **🎨 User-Centric Frontend** and **🏛️ Structure & Modularity** principles by creating a dedicated, clean, and reusable view.

### The "How"

We create a new directory `app/templates/alerts` and add the file `alert_detail.html` inside it.

```html
<!-- app/templates/alerts/alert_detail.html -->
{% extends "layouts/base.html" %}

{% block content %}
    <div class="breadcrumb">
        <a href="{{ url_for('dashboard.index') }}">← Back to Dashboard</a>
    </div>
    <h1>Alert Document Explorer</h1>
    <p>Full document for alert ID: <strong>{{ alert_id }}</strong></p>

    <div class="json-explorer">
        <!-- The <pre> tag preserves whitespace (like newlines and indents),
             which is perfect for showing our pretty-printed JSON. -->
        <pre><code>{{ alert_json }}</code></pre>
    </div>

    <!-- This section is pure UX: it helps the developer understand what they see -->
    <h2>What am I looking at?</h2>
    <p>
        This is the raw JSON document for a single alert, exactly as it is stored in the Wazuh indexer (Elasticsearch). It contains two main parts:
    </p>
    <ul>
        <li>
            <strong>Metadata (keys starting with `_`):</strong> Fields like <code>_index</code>, <code>_id</code>, and <code>_score</code> are added by Elasticsearch to manage the data. We use <code>_index</code> and <code>_id</code> to find this specific document.
        </li>
        <li>
            <strong>The Original Alert (the <code>_source</code> object):</strong> This is the heart of the data. Everything inside the <code>_source</code> object is the actual alert generated by Wazuh.
        </li>
    </ul>
{% endblock %}
```

**Key Features Explained:**

1.  **Template Inheritance**: `{% extends "layouts/base.html" %}` keeps our UI consistent. We don't have to repeat the `<html>`, `<head>`, or `<body>` tags. We just define the unique `content` for this page.
2.  **Breadcrumb Navigation**: The "Back to Dashboard" link is a crucial UX element. It prevents the user from feeling lost. `url_for('dashboard.index')` safely generates the correct URL to the main dashboard page.
3.  **Data Display**: We use `{{ alert_id }}` and `{{ alert_json }}` to insert the data we passed from our `routes.py` file. Jinja2 automatically escapes this data, protecting us from XSS attacks. The `<pre><code>` block is the standard, semantic way to display blocks of code or formatted text.

</details>

<br>

<details>
<summary><strong>Step 5: Connecting the Dots — Updating the Dashboard</strong></summary>

### The "Why"

Our new detail page exists, but there's no way to get to it! We need to go back to the dashboard and turn each static alert item into a link that points to our new route.

### The "How"

We modify the `app/templates/dashboard/index.html` file.

**Before:**

```html
<!-- ... -->
{% for alert in alerts %}
    <div class="activity-item">
        <div class="item-header">{{ alert._source.rule.description }}</div>
        <!-- ... -->
    </div>
{% endfor %}
<!-- ... -->
```

**After:**

```html
<!-- app/templates/dashboard/index.html -->
<!-- ... -->
{% for alert in alerts %}
    {# 
        CHANGE: We now pass both the index name and the alert ID.
        This makes our lookup far more precise.
    #}
    <a href="{{ url_for('alerts.detail', index_name=alert._index, alert_id=alert._id) }}" class="activity-link">
        <div class="activity-item">
            <div class="item-header">{{ alert._source.rule.description }}</div>
            <div class="item-meta">
                <span>Timestamp: {{ alert._source.timestamp }}</span>
                <span>Source IP: {{ alert._source.data.srcip if alert._source.data and 'srcip' in alert._source.data else 'N/A' }}</span>
                <span>Level: {{ alert._source.rule.level }}</span>
            </div>
        </div>
    </a>
{% endfor %}
<!-- ... -->
```

**The Crucial Change Explained:**

The `<a>` tag's `href` attribute is where the magic happens:
`{{ url_for('alerts.detail', index_name=alert._index, alert_id=alert._id) }}`

*   `url_for('alerts.detail', ...)`: This tells Jinja2 and Flask to generate a URL for the `detail` function inside our `alerts` blueprint.
*   `index_name=alert._index`: We are passing a keyword argument named `index_name` to `url_for`. Its value is taken from the alert data itself (`alert._index`). This corresponds to the `<string:index_name>` part of our route.
*   `alert_id=alert._id`: Similarly, we pass the `alert_id` argument, taking its value from `alert._id`. This corresponds to the `<string:alert_id>` part of our route.

Now, each item in the list becomes a fully functional link to the correct detail page.

</details>

<br>

<details>
<summary><strong>Step 6: Polishing the Look — CSS Styling</strong></summary>

### The "Why"

A functional UI is good, but an intuitive and pleasant UI is better. We need to add some CSS to style our new links on the dashboard and the JSON explorer on the detail page. This aligns with our **🎨 User-Centric Frontend** principle.

### The "How"

We update the one and only stylesheet: `app/static/css/style.css`.

```css
/* ... existing styles ... */

/* === Dashboard Styles === */
.activity-feed {
    /* ... */
    padding: 0; /* Change */
    overflow: hidden; /* Add */
}
/* NEW: Style the new anchor tag */
.activity-link {
    display: block;
    text-decoration: none;
    color: inherit;
    transition: background-color 0.2s ease-in-out;
}
.activity-link:hover {
    background-color: #2a2a2a;
}
.activity-item {
    padding: 15px 20px;
    border-bottom: 1px solid #333;
}
.activity-link:last-child .activity-item {
    border-bottom: none;
}

/* === NEW: Alert Detail Page Styles === */
.breadcrumb {
    margin-bottom: 20px;
}
.breadcrumb a {
    color: #00aaff;
    text-decoration: none;
    font-size: 0.9em;
}
.breadcrumb a:hover {
    text-decoration: underline;
}
.json-explorer {
    background-color: #1e1e1e;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
    overflow-x: auto; /* Allow horizontal scrolling for wide JSON */
}
.json-explorer pre {
    margin: 0;
    font-size: 0.9em;
    color: #d4d4d4;
}
```

**Styling Explained:**

*   `.activity-link`: We make the entire area of the alert item a clickable block and add a subtle hover effect to give the user visual feedback.
*   `.breadcrumb`: We style the "Back" link to be prominent but not distracting.
*   `.json-explorer`: We create a dark, code-like box for our JSON data. `overflow-x: auto;` is a key addition—if a line of JSON is very long, the user can scroll horizontally instead of breaking the entire page layout.

</details>

<br>

<details>
<summary><strong>Step 7: Final Integration — The Application Factory</strong></summary>

### The "Why"

We've built our new feature module, but the main application doesn't know it exists yet. We need to "register" our new `alerts` blueprint in the application factory (`create_app`). We also need to enable the debug logging we added in Step 2 so we can see our helpful log messages during development.

### The "How"

We make two small but important changes to `app/__init__.py`.

```python
# app/__init__.py

import logging  # <-- IMPORT LOGGING MODULE
from flask import Flask, request, redirect, url_for
# ... other imports

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # --- CHANGE: Configure Logging Level ---
    # This ensures that messages logged with app.logger.debug() will be displayed
    # in your terminal, which is essential for development and debugging.
    if app.debug:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
    # --- End Change ---

    # ... db, migrate, login_manager inits ...

    with app.app_context():
        # Import and register our blueprints
        from .auth import routes as auth_routes
        from .dashboard import routes as dashboard_routes
        from .alerts import routes as alert_routes # <-- IMPORT a new blueprint

        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(dashboard_routes.bp)
        app.register_blueprint(alert_routes.bp) # <-- REGISTER the new blueprint

        # ... rest of the file ...

    app.logger.info("LAMIS Application Created")
    return app
```

**Final Changes Explained:**

1.  **Registering the Blueprint**: `app.register_blueprint(alert_routes.bp)` is the final step that tells Flask about all the routes, templates, and static files associated with our `alerts` module. Without this line, the `/alert/...` URLs would give a 404 error.
2.  **Configuring the Logger**: Setting the logger level to `DEBUG` when the app is in debug mode (`FLASK_DEBUG=1`) "unlocks" the `app.logger.debug(...)` messages we wrote in our service layer. This is invaluable for tracing how our code is executing and what data it's working with.

---

