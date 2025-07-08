# Tutorial: Refactoring LAMIS for Multi-Manager Support

The original version of LAMIS was built with a single, hardcoded connection to one Wazuh manager. This worked, but it wasn't scalable or flexible. Our goal is to transform the application to support **multiple Wazuh manager APIs**, allowing us to aggregate security alerts from different environments into a single, unified dashboard.

This process will teach you about:
*   **Secure Credential Storage:** How to encrypt sensitive data like API passwords in a database.
*   **Database Migrations:** The professional way to update your database schema.
*   **Modular Application Design:** Building a new, self-contained feature using Flask Blueprints.
*   **Concurrent Programming:** Using threads to fetch data from multiple sources simultaneously for better performance.
*   **Defensive Programming:** Writing code that anticipates and handles errors gracefully.

We will proceed step-by-step. Complete each step fully before moving to the next. If you feel overwhelmed, take a break. Each major step is a self-contained unit of progress.

Let's begin the build.

---

<details>
<summary>
<h2>Step 1: Environment Setup (The Foundation)</h2>
</summary>

Before we write a single line of application code, we need to prepare our environment. This involves installing a new library for encryption and generating a master encryption key.

### 1.1. Install the Cryptography Library

Our new design will store Wazuh API passwords in the database. Storing them as plain text would be a major security vulnerability. Instead, we will encrypt them. The `cryptography` library is the industry standard in Python for this task.

Open your terminal, activate your virtual environment, and run:

```bash
pip install cryptography
```

Now, update your `req.txt` file to include this new dependency.

<details>
<summary>Click here to see the new <code>req.txt</code> file.</summary>

```python
# Practice/req.txt

# The main engine for our web app
Flask

# For building and validating forms without wanting to cry
Flask-WTF

# Manages user login sessions (who is logged in?)
Flask-Login

# The magic that lets us talk to a database with Python instead of raw SQL
Flask-SQLAlchemy

# Like Git for your database structure. An absolute lifesaver.
Flask-Migrate

# The specific "translator" for talking to a PostgreSQL database
psycopg2-binary

# For securely scrambling passwords
Werkzeug

# Lets us load secret stuff from a file instead of hardcoding it
python-dotenv

# For encrypting/decrypting sensitive data like API keys at rest
cryptography
```
</details>

### 1.2. Generate and Store the Master Encryption Key

We need a single, secret key that our application will use to encrypt and decrypt all the Wazuh passwords. This key **must not** be stored in our code. Like all secrets, it belongs in our `.env` file.

**A. Generate the Key:**
Run the following command in your terminal. It will print a unique, securely-generated key.

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

It will output a long string of random characters, something like this: `T2gVQu33n5q1Y4G7y8z...`. **Copy the key you generated.**

**B. Add the Key to `.env`:**
Open your `.env` file and add a new line for `ENCRYPTION_KEY`. Paste the key you just generated.

Your `.env` file should now look something like this:

```dotenv
# .env

# Your Flask Secret Key (for sessions, CSRF)
SECRET_KEY='a-very-secret-and-long-random-string'

# Your Database Connection URL
DATABASE_URL='postgresql://postgres:password@localhost:5432/orm_db'

# NEW: The master key for encrypting other secrets in the database
ENCRYPTION_KEY='T2gVQu33n5q1Y4G7y8z...' # <-- PASTE YOUR GENERATED KEY HERE
```

**Why do we do this?**
This is a security best practice called **envelope encryption**.
*   The `ENCRYPTION_KEY` is the "master key." It's kept safe in the environment.
*   When we save a Wazuh password, we use this key to encrypt it. The encrypted version is what gets stored in the database.
*   If an attacker ever gets a dump of our database, the passwords are just meaningless gibberish. They are useless without the `ENCRYPTION_KEY`, which is stored separately.

With our environment ready, we can now build the core database component.

</details>

---

<details>
<summary>
<h2>Step 2: The Database Layer (The Blueprint for Data)</h2>
</summary>

Our biggest architectural change is moving from hardcoded config variables to storing Wazuh manager details in the database. This requires a new database table, which we define with a SQLAlchemy model.

### 2.1. Create the `WazuhManager` Model

Create a new file: `app/models/wazuh.py`. This file will define the structure of our `wazuh_managers` table and, crucially, how to handle the password encryption.

**File: `app/models/wazuh.py`**
```python
from typing import Optional
from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy.ext.hybrid import hybrid_property

from app.models import db


class WazuhManager(db.Model):
    __tablename__ = "wazuh_managers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    url = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    # This stores the raw encrypted bytes of the password
    _encrypted_password = db.Column(
        "encrypted_password", db.LargeBinary, nullable=False
    )
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<WazuhManager {self.name}>"

    @staticmethod
    def _get_crypter() -> Fernet:
        """Helper to get the Fernet instance with the app's secret key."""
        key = current_app.config.get("ENCRYPTION_KEY")
        if not key:
            raise ValueError("ENCRYPTION_KEY is not set in the application config!")
        return Fernet(key.encode())

    @hybrid_property
    def password(self) -> Optional[str]:
        """
        A hybrid property that decrypts the password when accessed.
        This will return the decrypted password as a string.
        It's a 'property', so you access it like `manager.password` not `manager.password()`.
        """
        if not self._encrypted_password:
            return None
        crypter = self._get_crypter()
        try:
            return crypter.decrypt(self._encrypted_password).decode()
        except Exception:
            # If decryption fails for any reason, return None safely
            return None

    @password.setter
    def password(self, plaintext_password: str) -> None:
        """
        Encrypts the given plaintext password and stores it in the _encrypted_password field.
        This is called automatically when you do `manager.password = 'my-secret-pass'`.
        """
        crypter = self._get_crypter()
        self._encrypted_password = crypter.encrypt(plaintext_password.encode())

    def get_decrypted_password(self, key: str) -> Optional[str]:
        """
        Decrypts the password using a provided key.
        This is for use outside of the standard Flask request context (e.g., in threads).
        """
        if not self._encrypted_password:
            return None
        crypter = Fernet(key.encode())
        try:
            return crypter.decrypt(self._encrypted_password).decode()
        except Exception:
            return None
```

**Code Explanation:**
*   **`_encrypted_password`**: We name this field with a leading underscore `_` to signal that it's for internal use. It stores the raw, encrypted bytes of the password.
*   **`@hybrid_property def password(...)`**: This is the "getter." It allows us to access `manager.password` in our code. When we do, this function runs automatically, fetches the `ENCRYPTION_KEY`, decrypts the `_encrypted_password` bytes, and returns a normal string. This makes using the model incredibly clean.
*   **`@password.setter def password(...)`**: This is the "setter." It's called automatically whenever we assign a value, like `manager.password = 'my-secret-pass'`. It takes the plain text password, encrypts it, and stores the result in the `_encrypted_password` field.
*   **`get_decrypted_password(self, key)`**: This is a special helper method. We need it because our background threads (which we'll create later) won't have access to Flask's `current_app`. This method allows us to explicitly pass the encryption key to them for decryption.

### 2.2. Update Configuration and Database Initialization

Now we need to tell our app about this new model and update our configuration.

**A. Update `config.py`**
Remove the old, single-source Wazuh variables and add a line to load our new `ENCRYPTION_KEY`.

**File: `config.py`**
```python
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__name__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # NEW: The master key for encrypting credentials in the database.
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

    # REMOVED: These are no longer the source of truth.
    # WAZUH_URL = os.environ.get("WAZUH_URL")
    # WAZUH_USER = os.environ.get("WAZUH_USER")
    # WAZUH_PASS = os.environ.get("WAZUH_PASS")
```

**B. Update `app/models/__init__.py`**
Import the new model here to ensure SQLAlchemy knows about it when we run migrations.

**File: `app/models/__init__.py`**
```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import models here so they are registered with SQLAlchemy
from app.models.wazuh import WazuhManager
```

### 2.3. Run the Database Migration

We have defined a new table in our code, but our actual PostgreSQL database doesn't know about it yet. We use `flask-migrate` to bridge this gap.

**A. Create the Migration Script:**
This command compares our models to the database schema and generates a Python script describing the changes (in our case, creating the `wazuh_managers` table).

```bash
flask db migrate -m "Add wazuh_managers table"
```
You will see a new file appear under a `migrations/versions/` directory.

**B. Apply the Migration:**
This command runs the script and actually creates the table in your database.

```bash
flask db upgrade
```

Your database is now up-to-date with our new application structure. We are ready to build the user interface for managing these Wazuh instances.

</details>

---

<details>
<summary>
<h2>Step 3: Building the "Managers" Module (A New Feature)</h2>
</summary>

This is the most exciting part. We will build a completely new, self-contained module for adding, viewing, editing, and deleting Wazuh managers. This is a perfect demonstration of the **Flask Blueprints** and **Service Layer** principles.

### 3.1. Create the Module Structure

First, create the new directory and empty files for our `managers` blueprint.

```
app/
└── managers/
    ├── __init__.py      (empty)
    ├── forms.py
    ├── routes.py
    └── services.py
```

### 3.2. Create the Manager Form

This form will be used for both adding new managers and editing existing ones.

**File: `app/managers/forms.py`**
```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, URL


class WazuhManagerForm(FlaskForm):
    """Form for adding or editing a Wazuh Manager instance."""

    name = StringField(
        "Display Name",
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g., Production Cluster"},
    )
    url = StringField(
        "Wazuh API URL",
        validators=[DataRequired(), URL(message="Please enter a valid URL.")],
        render_kw={"placeholder": "e.g., https://192.168.1.10:9200"},
    )
    username = StringField(
        "API Username",
        validators=[DataRequired()],
        render_kw={"placeholder": "e.g., admin"},
    )
    password = PasswordField("API Password", validators=[DataRequired()])
    submit = SubmitField("Save and Test Connection")
```

### 3.3. Create the Service Logic

The service layer contains our core "business logic." Here, we'll put the function that tests the connection to a Wazuh manager. This keeps our routes clean and the logic reusable.

**File: `app/managers/services.py`**
```python
from typing import Tuple, Literal
import requests
from flask import current_app

from app.models import db
from app.models.wazuh import WazuhManager

# Define a type for our connection status to ensure consistency
ConnectionStatus = Literal["success", "auth_error", "connection_error", "unknown_error"]


def test_wazuh_connection(
    manager: WazuhManager,
    encryption_key: str = None,
    logger=None,
) -> Tuple[bool, ConnectionStatus, str]:
    """
    Tests the connection to a single Wazuh manager.
    Can be used both inside and outside the Flask app context.
    Args:
        manager: A WazuhManager object.
        encryption_key: The app's encryption key, required if running outside app context.
        logger: The app's logger, optional.
    Returns:
        A tuple containing: (success_boolean, status_code, message)
    """
    log = logger or current_app.logger
    key = encryption_key or current_app.config["ENCRYPTION_KEY"]

    # Decrypt password manually for use in threads
    password = manager.get_decrypted_password(key)
    if not password:
        msg = "Could not decrypt password. Key may be invalid."
        log.error(f"{manager.name}: {msg}")
        return (False, "auth_error", msg)

    test_url = manager.url
    log.info(f"Testing connection to {manager.name} at {test_url}...")

    try:
        with requests.Session() as session:
            session.auth = (manager.username, password)
            # Use a short timeout to avoid long waits for unresponsive servers
            response = session.get(test_url, verify=False, timeout=5)

            if response.status_code == 200:
                # Extra check to see if it's actually a Wazuh/Elasticsearch API
                data = response.json()
                if "cluster_name" in data:
                    msg = f"Successfully connected to {manager.name}."
                    log.info(msg)
                    return (True, "success", msg)
                else:
                    msg = "Connected, but the response does not look like a Wazuh API."
                    log.warning(f"{manager.name}: {msg}")
                    return (False, "connection_error", msg)

            elif response.status_code in [401, 403]:
                msg = "Authentication failed. Please check username and password."
                log.warning(f"{manager.name}: {msg}")
                return (False, "auth_error", msg)
            else:
                msg = f"Received an unexpected status code: {response.status_code}."
                log.error(f"{manager.name}: {msg}")
                return (False, "connection_error", msg)

    except requests.exceptions.Timeout:
        msg = "Connection timed out. The server is unreachable or slow."
        log.error(f"{manager.name}: {msg}")
        return (False, "connection_error", msg)
    except requests.exceptions.ConnectionError:
        msg = "Connection failed. Check the URL and network connectivity."
        log.error(f"{manager.name}: {msg}")
        return (False, "connection_error", msg)
    except Exception as e:
        msg = f"An unknown error occurred: {e}"
        log.error(f"{manager.name}: {msg}")
        return (False, "unknown_error", msg)
```
**Code Explanation:**
*   This function takes a `WazuhManager` object and performs a series of checks.
*   It uses extensive `try...except` blocks to handle all likely failure scenarios: timeouts, network errors, authentication failures, etc.
*   It returns a clear, consistent tuple `(True/False, status_code, message)` which our routes can use to give feedback to the user.

### 3.4. Create the Routes

The routes are the "glue" that connect HTTP requests from the user's browser to our forms and service logic.

**File: `app/managers/routes.py`**
```python
from flask import render_template, redirect, url_for, flash, Blueprint, request
from flask_login import login_required

from app.models import db
from app.models.wazuh import WazuhManager
from app.managers.forms import WazuhManagerForm
from app.managers.services import test_wazuh_connection

bp = Blueprint("managers", __name__, url_prefix="/managers")


@bp.route("/setup", methods=["GET", "POST"])
@login_required
def setup_wazuh():
    """Route for the initial setup of the first Wazuh manager."""
    if WazuhManager.query.count() > 0:
        # If a manager already exists, they shouldn't be here. Send to dashboard.
        return redirect(url_for("dashboard.index"))

    form = WazuhManagerForm()
    if form.validate_on_submit():
        new_manager = WazuhManager(
            name=form.name.data,
            url=form.url.data,
            username=form.username.data,
        )
        # The password setter in the model handles encryption automatically
        new_manager.password = form.password.data

        # Test the connection BEFORE saving to the database
        is_ok, status, message = test_wazuh_connection(new_manager)

        if is_ok:
            db.session.add(new_manager)
            db.session.commit()
            flash("Wazuh manager configured successfully! Welcome to LAMIS.", "success")
            return redirect(url_for("dashboard.index"))
        else:
            flash(f"Connection failed: {message}", "danger")

    return render_template("managers/setup_wazuh.html", form=form)


@bp.route("/manage", methods=["GET", "POST"])
@bp.route("/manage/<int:edit_id>", methods=["GET", "POST"])
@login_required
def manage(edit_id=None):
    """Route for viewing, adding, and deleting managers."""
    form = WazuhManagerForm()
    edit_manager = None

    if edit_id:
        edit_manager = WazuhManager.query.get_or_404(edit_id)
        if request.method == "GET":
            # Pre-populate form with existing data
            form.name.data = edit_manager.name
            form.url.data = edit_manager.url
            form.username.data = edit_manager.username
            form.submit.label.text = "Update and Test Connection"

    if form.validate_on_submit():
        if edit_manager:
            # Update existing manager
            edit_manager.name = form.name.data
            edit_manager.url = form.url.data
            edit_manager.username = form.username.data
            edit_manager.password = form.password.data

            is_ok, status, message = test_wazuh_connection(edit_manager)
            if is_ok:
                db.session.commit()
                flash(f"Manager '{edit_manager.name}' updated successfully.", "success")
                return redirect(url_for("managers.manage"))
            else:
                flash(
                    f"Could not update manager. Connection failed: {message}", "danger"
                )
        else:
            # Add new manager
            new_manager = WazuhManager(
                name=form.name.data,
                url=form.url.data,
                username=form.username.data,
            )
            new_manager.password = form.password.data

            is_ok, status, message = test_wazuh_connection(new_manager)
            if is_ok:
                db.session.add(new_manager)
                db.session.commit()
                flash(f"Manager '{new_manager.name}' added successfully.", "success")
                return redirect(url_for("managers.manage"))
            else:
                flash(f"Could not add manager. Connection failed: {message}", "danger")

    managers = WazuhManager.query.order_by(WazuhManager.name).all()
    return render_template(
        "managers/manage.html", form=form, managers=managers, edit_manager=edit_manager
    )


@bp.route("/delete/<int:manager_id>", methods=["POST"])
@login_required
def delete(manager_id: int):
    manager = WazuhManager.query.get_or_404(manager_id)
    db.session.delete(manager)
    db.session.commit()
    flash(f"Manager '{manager.name}' has been deleted.", "success")
    return redirect(url_for("managers.manage"))
```
**Code Explanation:**
*   **`setup_wazuh`**: A special route for the *first-time* setup.
*   **`manage`**: A powerful route that handles viewing all managers, adding a new one, and editing an existing one. It uses the `edit_id` URL parameter to decide which mode it's in.
*   **`delete`**: A simple route that handles deleting a manager.
*   **Notice the pattern**: The routes are "thin." They handle the form, call the `test_wazuh_connection` service, interact with the database, and then `flash` a message and `redirect`. The complex logic is kept in the service.

### 3.5. Create the Templates

Now create the HTML files that the user will see.

First, create the new directory: `app/templates/managers/`.

<details>
<summary>Click to see <code>app/templates/managers/setup_wazuh.html</code></summary>

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS - Configure Wazuh</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/auth.css') }}">
</head>
<body>
    <div class="auth-container">
        <h1>Connect to Wazuh</h1>
        <p class="subtitle">Add your first Wazuh Manager to begin monitoring.</p>
        
        <div class="flash-messages">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        </div>

        <form action="" method="post" novalidate>
            {{ form.hidden_tag() }}
            <div class="form-group">
                {{ form.name.label }}
                {{ form.name(class="form-control") }}
                {% for error in form.name.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.url.label }}
                {{ form.url(class="form-control") }}
                {% for error in form.url.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.username.label }}
                {{ form.username(class="form-control") }}
                {% for error in form.username.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.password.label }}
                {{ form.password(class="form-control") }}
                {% for error in form.password.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.submit(class="btn-submit") }}
            </div>
        </form>
    </div>
</body>
</html>
```
</details>

<details>
<summary>Click to see <code>app/templates/managers/manage.html</code></summary>

```html
{% extends "layouts/base.html" %}

{% block content %}
    <div class="page-header">
        <div class="header-actions">
            <a href="{{ url_for('dashboard.index') }}" class="btn btn-back">
                <i class="fi fi-br-arrow-left"></i> Back to Dashboard
            </a>
        </div>
        <h1>Manage Wazuh Managers</h1>
        <p>View, add, or remove your Wazuh API connections.</p>
    </div>
    
    <div class="flash-messages">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <div class="management-grid">
        <div class="manager-list card">
            <h2>Configured Managers</h2>
            {% if managers %}
                <ul>
                {% for manager in managers %}
                    <li {% if edit_manager and edit_manager.id == manager.id %}class="editing"{% endif %}>
                        <div class="manager-info">
                            <strong>{{ manager.name }}</strong>
                            <span class="manager-url">{{ manager.url }}</span>
                        </div>
                        <div class="manager-actions">
                            {% if not edit_manager or edit_manager.id != manager.id %}
                                <a href="{{ url_for('managers.manage', edit_id=manager.id) }}" class="btn btn-edit">
                                    <i class="fi fi-br-pencil"></i> Edit
                                </a>
                            {% else %}
                                <a href="{{ url_for('managers.manage') }}" class="btn btn-cancel">
                                    <i class="fi fi-br-cross"></i> Cancel
                                </a>
                            {% endif %}
                            <form action="{{ url_for('managers.delete', manager_id=manager.id) }}" method="post" style="display: inline;">
                                <input type="submit" value="Delete" class="btn btn-delete" onclick="return confirm('Are you sure you want to delete this manager?');">
                            </form>
                        </div>
                    </li>
                {% endfor %}
                </ul>
            {% else %}
                <p>No managers configured yet. Add your first manager using the form on the right.</p>
            {% endif %}
        </div>

        <div class="add-manager-form card">
            <h2>{% if edit_manager %}Edit Manager{% else %}Add New Manager{% endif %}</h2>
            {% if edit_manager %}
                <div class="edit-notice">
                    <i class="fi fi-br-info"></i>
                    You are editing: <strong>{{ edit_manager.name }}</strong>
                </div>
            {% endif %}
            <form action="{% if edit_manager %}{{ url_for('managers.manage', edit_id=edit_manager.id) }}{% else %}{{ url_for('managers.manage') }}{% endif %}" method="post" novalidate>
                {{ form.hidden_tag() }}
                <p>
                    {{ form.name.label }}
                    {{ form.name(size=32, placeholder="e.g., Production Wazuh") }}
                </p>
                <p>
                    {{ form.url.label }}
                    {{ form.url(size=32, placeholder="https://your-wazuh-manager:55000") }}
                </p>
                <p>
                    {{ form.username.label }}
                    {{ form.username(size=32, placeholder="wazuh-api-user") }}
                </p>
                <p>
                    {{ form.password.label }}
                    {{ form.password(size=32, placeholder="{% if edit_manager %}Leave blank to keep current password{% else %}Your API password{% endif %}") }}
                </p>
                <div class="form-actions">
                    <p>{{ form.submit() }}</p>
                    {% if edit_manager %}
                        <a href="{{ url_for('managers.manage') }}" class="btn btn-secondary">Cancel Edit</a>
                    {% endif %}
                </div>
            </form>
        </div>
    </div>
{% endblock %}
```
</details>

We have now built a complete, functional, and secure module for managing our Wazuh connections. The next step is to refactor the rest of the application to *use* this new system.

</details>

---

<details>
<summary>
<h2>Step 4: Refactoring the Core Application</h2>
</summary>

With our new `managers` module in place, we need to update the dashboard and alert details pages to query multiple sources. We also need to adjust the application's startup and authentication flow.

### 4.1. Update the Dashboard for Concurrent Fetching

The dashboard is the most critical change. Instead of fetching alerts from one hardcoded URL, it must now query all active managers in the database, do it efficiently, and combine the results.

**File: `app/dashboard/services.py`**
```python
import requests
from flask import current_app
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models.wazuh import WazuhManager
from app.managers.services import test_wazuh_connection, ConnectionStatus


def _fetch_alerts_from_manager(
    manager: WazuhManager, limit: int, encryption_key: str, logger
) -> List[Dict[str, Any]]:
    """Fetches alerts from a single, specific Wazuh manager instance."""
    wazuh_url: str = f"{manager.url}/wazuh-alerts-*/_search"
    query: Dict[str, Any] = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }

    password = manager.get_decrypted_password(encryption_key)
    if not password:
        logger.error(f"Could not decrypt password for {manager.name}, skipping.")
        return []

    logger.debug(f"Fetching alerts from manager: {manager.name}")
    try:
        with requests.Session() as session:
            session.auth = (manager.username, password)
            response: requests.Response = session.post(
                wazuh_url, json=query, verify=False, timeout=15
            )
            response.raise_for_status()

            data: Dict[str, Any] = response.json()
            alerts = data.get("hits", {}).get("hits", [])

            # Add source context to each alert for the UI
            for alert in alerts:
                alert["_source_manager_name"] = manager.name
                alert["_source_manager_id"] = manager.id

            return alerts

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch alerts from {manager.name} ({manager.url}): {e}")
        return []


def get_all_wazuh_alerts(limit_per_manager: int = 20) -> List[Dict[str, Any]]:
    """Fetches alerts from ALL active Wazuh managers concurrently and aggregates them."""
    active_managers = WazuhManager.query.filter_by(is_active=True).all()

    if not active_managers:
        return []

    # Pass the key and logger to the threads
    key = current_app.config["ENCRYPTION_KEY"]
    log = current_app.logger

    all_alerts = []
    with ThreadPoolExecutor(max_workers=len(active_managers) or 1) as executor:
        future_to_manager = {
            executor.submit(
                _fetch_alerts_from_manager, manager, limit_per_manager, key, log
            ): manager
            for manager in active_managers
        }

        for future in as_completed(future_to_manager):
            manager = future_to_manager[future]
            try:
                alerts_from_manager = future.result()
                all_alerts.extend(alerts_from_manager)
            except Exception as exc:
                log.error(f"Manager {manager.name} generated an exception: {exc}")

    all_alerts.sort(key=lambda x: x["_source"]["timestamp"], reverse=True)
    return all_alerts


def get_managers_status() -> List[Tuple[WazuhManager, bool, ConnectionStatus, str]]:
    """
    Checks the connection status of all active managers concurrently.

    Returns:
        A list of tuples, where each tuple contains:
        (manager_object, is_ok, status_code, message)
    """
    active_managers = WazuhManager.query.filter_by(is_active=True).all()
    results = []

    if not active_managers:
        return []

    key = current_app.config["ENCRYPTION_KEY"]
    log = current_app.logger

    with ThreadPoolExecutor(max_workers=len(active_managers) or 1) as executor:
        future_to_manager = {
            executor.submit(test_wazuh_connection, manager, key, log): manager
            for manager in active_managers
        }
        for future in as_completed(future_to_manager):
            manager = future_to_manager[future]
            try:
                is_ok, status_code, message = future.result()
                results.append((manager, is_ok, status_code, message))
            except Exception as exc:
                log.error(
                    f"Status check for {manager.name} generated an exception: {exc}"
                )
                results.append((manager, False, "unknown_error", str(exc)))

    return results
```
**Code Explanation:**
*   **`ThreadPoolExecutor`**: This is the key to performance. Instead of asking each Wazuh manager for alerts one-by-one, we create a "pool" of worker threads. Each thread is assigned one manager to query. They all run at the same time. This is dramatically faster.
*   **`_fetch_alerts_from_manager`**: A helper function that contains the logic for fetching alerts from just one manager. This is what each thread will run.
*   **`get_all_wazuh_alerts`**: The main function. It gets all managers, sets up the thread pool, collects the results, and sorts them by timestamp to create a unified timeline.
*   **`get_managers_status`**: A new function that also uses a thread pool to quickly check the connection status of all managers. This will power our new dashboard status card.
*   **Context Injection**: Notice the lines `alert["_source_manager_name"] = manager.name` and `alert["_source_manager_id"] = manager.id`. This is critical. We are adding information to each alert so that our frontend knows which manager it came from.

Now, update the dashboard route to use these new services.

**File: `app/dashboard/routes.py`**
```python
from flask import render_template, Blueprint, flash
from flask_login import login_required
from app.dashboard.services import get_all_wazuh_alerts, get_managers_status

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    manager_statuses = get_managers_status()

    # Check for any failures and flash a message
    failed_managers = [s for s in manager_statuses if not s[1]]
    if failed_managers:
        for manager, is_ok, status, message in failed_managers:
            flash(f"Connection Error for '{manager.name}': {message}", "danger")

    # Fetch alerts regardless of connection status (it might be a temporary blip)
    latest_alerts = get_all_wazuh_alerts(limit_per_manager=15)

    return render_template(
        "dashboard/index.html", alerts=latest_alerts, manager_statuses=manager_statuses
    )
```

### 4.2. Update the Alert Detail Page

The alert detail page now needs to know *which* manager to query. We will add a `manager_id` to its URL and pass that to the service function.

**File: `app/alerts/services.py`**
```python
# app/alerts/services.py

import json
from typing import Dict, Any, Optional

import requests
from flask import current_app

# NEW: Import the WazuhManager model to get connection details.
from app.models.wazuh import WazuhManager


def get_wazuh_alert_by_id(
    manager_id: int, index_name: str, alert_id: str
) -> Optional[Dict[str, Any]]:
    """
    Fetches a single Wazuh alert document by its ID from a specific index
    on a specific Wazuh manager.

    This uses the more precise GET /<index>/_doc/<id> endpoint.

    Args:
        manager_id: The ID of the WazuhManager to query.
        index_name: The specific index the alert resides in.
        alert_id: The unique _id of the Wazuh alert document.

    Returns:
        A dictionary containing the full alert document (including metadata),
        or None if the alert is not found or an error occurs.
    """
    # 1. Get the specific manager from the database.
    manager = WazuhManager.query.get(manager_id)
    if not manager:
        current_app.logger.error(
            f"Attempted to fetch alert from a non-existent manager with ID: {manager_id}"
        )
        return None

    # 2. Get credentials. The hybrid property decrypts the password automatically.
    password = manager.password
    if not password:
        current_app.logger.error(
            f"Could not decrypt password for manager '{manager.name}'."
        )
        return None

    # 3. Construct a URL to fetch a single document directly from the correct manager.
    wazuh_url: str = f"{manager.url}/{index_name}/_doc/{alert_id}"

    current_app.logger.debug(
        f"Attempting to fetch alert document '{alert_id}' from index '{index_name}' on manager '{manager.name}'."
    )
    current_app.logger.debug(f"Request URL: {wazuh_url}")

    try:
        with requests.Session() as session:
            # 4. Use the manager-specific credentials for auth.
            session.auth = (manager.username, password)
            response: requests.Response = session.get(
                wazuh_url, verify=False, timeout=10
            )

            current_app.logger.debug(f"Received status code: {response.status_code}")
            response.raise_for_status()

            full_document: Dict[str, Any] = response.json()

            if full_document.get("found") is True:
                current_app.logger.info(
                    f"Successfully fetched alert document '{alert_id}'."
                )
                return full_document
            else:
                current_app.logger.warning(
                    f"API reported success, but document '{alert_id}' was not found."
                )
                return None

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            current_app.logger.warning(
                f"Wazuh alert document with ID '{alert_id}' not found in index '{index_name}'. (404)"
            )
        else:
            current_app.logger.error(
                f"HTTP error fetching alert '{alert_id}': {http_err}"
            )
        return None
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Failed to fetch alert '{alert_id}' from Wazuh: {e}")
        return None


def format_json_for_html(data: Dict[str, Any]) -> str:
    """
    Converts a Python dictionary to a pretty-printed JSON string.
    """
    return json.dumps(data, indent=4, sort_keys=True)
```

**File: `app/alerts/routes.py`**
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
# e.g., /alert/1/wazuh-alerts-4.x-2024.01.01/ABCDEFG will call:
# detail(manager_id=1, index_name="wazuh-alerts-4.x-2024.01.01", alert_id="ABCDEFG")
@bp.route("/<int:manager_id>/<string:index_name>/<string:alert_id>")
@login_required  # Security: Ensures only logged-in users can see this page.
def detail(manager_id: int, index_name: str, alert_id: str):
    """
    Displays the full details of a single Wazuh alert from a specific index.
    """
    # 1. Call the service to do the heavy lifting, now with manager_id.
    alert_data = get_wazuh_alert_by_id(
        manager_id=manager_id, index_name=index_name, alert_id=alert_id
    )

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

### 4.3. Update the Authentication and Application Setup Flow

Finally, we tie it all together in the main application factory and the authentication routes.

**A. Update `auth/routes.py`**
After the initial admin user is created, we should not send them to the dashboard (which would be empty). Instead, we now redirect them to the new Wazuh setup page.

**File: `app/auth/routes.py`**
*Only the `setup` function is changed. The rest of the file remains the same.*
```python
# ... imports ...
@bp.route("/setup", methods=["GET", "POST"])
def setup():
    state = InitializationState.query.first()
    if state and state.setup_completed:
        return redirect(url_for("dashboard.index"))

    form = SetupForms()

    if form.validate_on_submit():
        admin = User(username=form.username.data)
        admin.set_password(form.password.data)
        db.session.add(admin)

        state.setup_completed = True
        db.session.add(state)

        db.session.commit()

        login_user(admin)

        # CHANGE: Instead of going to the dashboard, we now go to the Wazuh setup page.
        flash(
            "Admin account created. Now, let's connect to your Wazuh manager.",
            "success",
        )
        return redirect(url_for("managers.setup_wazuh"))

    return render_template("auth/setup.html", form=form)

# ... login() and logout() functions are unchanged ...
```

**B. Update `app/__init__.py`**
This is the heart of the application startup. We need to register our new `managers` blueprint and, most importantly, update the `before_request` hook to enforce our new, multi-stage setup process.

**File: `app/__init__.py`**
```python
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from config import Config
from flask_sqlalchemy import SQLAlchemy
from app.models import db
from app.models.user import User
from app.models.state import InitializationState
import logging

# NEW: Import the WazuhManager model
from app.models.wazuh import WazuhManager

login_manager = LoginManager()
migrate = Migrate()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if app.debug:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    with app.app_context():
        from .auth import routes as auth_routes
        from .dashboard import routes as dashboard_routes
        from .alerts import routes as alert_routes

        # NEW: Import and register the managers blueprint
        from .managers import routes as manager_routes

        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(dashboard_routes.bp)
        app.register_blueprint(alert_routes.bp)
        app.register_blueprint(manager_routes.bp)

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        @app.before_request
        def check_initialization():
            """
            This hook runs before every request and enforces the setup flow.
            1. Is the database initialized? If not, run cli command.
            2. Is the admin user created? If not, redirect to /auth/setup.
            3. Is at least one Wazuh manager configured? If not, redirect to /managers/setup.
            """
            # Allow requests to static files and the setup endpoints themselves
            if request.endpoint and (
                request.endpoint.startswith("static")
                or request.endpoint in ["auth.setup", "managers.setup_wazuh"]
            ):
                return

            state = InitializationState.query.first()
            if not state or not state.setup_completed:
                return redirect(url_for("auth.setup"))

            # If setup is complete, but user is not logged in, let login_manager handle it
            if not current_user.is_authenticated:
                return  # login_manager will redirect to login page

            # NEW: Check if any Wazuh managers are configured.
            if WazuhManager.query.count() == 0:
                # If we are here, it means admin is created but no managers exist.
                # Send them to the Wazuh setup page.
                return redirect(url_for("managers.setup_wazuh"))

        @app.cli.command("init-state")
        def init_state_command():
            if InitializationState.query.first():
                print("Already Initialized >:( ")
                return

            initial_state = InitializationState(setup_completed=False)
            db.session.add(initial_state)
            db.session.commit()
            print("DATABASE INIT FINISHED ^OwO^/")

    app.logger.info("LAMIS Application Created")

    return app
```

</details>

---

<details>
<summary>
<h2>Step 5: Frontend and Styling Updates</h2>
</summary>

The backend is complete. Now we just need to update our templates and CSS to display the new data and reflect our new, more professional design.

### 5.1. Update Stylesheets

We have new CSS files and updates to existing ones. For these, you can simply copy and paste the content.

*   Create new file `app/static/css/auth.css`
*   Create new file `app/static/css/dashboard.css`
*   Create new file `app/static/css/manager.css`
*   Update the existing `app/static/css/style.css`

<details>
<summary>Click to see all CSS file contents</summary>

**File: `app/static/css/auth.css`**
```css
:root {
    --background-color: #121212;
    --surface-color: #1e1e1e;
    --primary-text-color: #e0e0e0;
    --secondary-text-color: #888;
    --primary-color: #4a90e2;
    --border-color: #333;
    --danger-color: #e57373;
    --success-color: #81c784;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--background-color);
    color: var(--primary-text-color);
    margin: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}

.auth-container {
    background-color: var(--surface-color);
    padding: 40px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    width: 100%;
    max-width: 400px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}

h1 {
    text-align: center;
    margin-top: 0;
    margin-bottom: 10px;
    color: #ffffff;
}

p.subtitle {
    text-align: center;
    color: var(--secondary-text-color);
    margin-top: 0;
    margin-bottom: 30px;
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    font-size: 0.9em;
}

.form-group input {
    width: 100%;
    padding: 12px;
    background-color: var(--background-color);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--primary-text-color);
    box-sizing: border-box;
    transition: border-color 0.2s;
}

.form-group input:focus {
    outline: none;
    border-color: var(--primary-color);
}

.form-group .error {
    color: var(--danger-color);
    font-size: 0.8em;
    margin-top: 5px;
}

.btn-submit {
    width: 100%;
    padding: 12px;
    background-color: var(--primary-color);
    border: none;
    border-radius: 4px;
    color: #ffffff;
    font-weight: bold;
    cursor: pointer;
    transition: background-color 0.2s;
}

.btn-submit:hover {
    background-color: #357abd;
}

.flash-messages .alert-danger {
    background-color: rgba(229, 115, 115, 0.1);
    color: var(--danger-color);
    border: 1px solid var(--danger-color);
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 20px;
}

.flash-messages .alert-success {
    background-color: rgba(129, 199, 132, 0.1);
    color: var(--success-color);
    border: 1px solid var(--success-color);
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 20px;
}
```

**File: `app/static/css/dashboard.css`**
```css
.activity-feed {
    margin-top: 20px;
    background-color: var(--surface-color);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 24px;
}

.activity-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid var(--border-color);
}

.activity-header h2 {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.4em;
    color: var(--primary-text-color);
}

.activity-header h2 i {
    color: var(--primary-color);
}

.activity-count {
    background: var(--surface-color);
    border: 1px solid var(--border-color);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.85em;
    color: var(--secondary-text-color);
}

.activity-list {
    display: flex;
    flex-direction: column;
    gap: 0;
}

.activity-link {
    text-decoration: none !important;
    color: inherit;
    display: block;
}

.activity-link:hover,
.activity-link:visited,
.activity-link:focus {
    text-decoration: none !important;
    color: inherit;
}

.activity-item {
    display: flex !important;
    align-items: center;
    padding: 16px !important;
    background: #21262d !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    transition: all 0.2s ease;
    cursor: pointer;
    margin-bottom: 12px !important;
    position: relative;
}

.activity-item:last-child {
    margin-bottom: 0 !important;
}

.activity-item:hover {
    background: rgba(88, 166, 255, 0.1) !important;
    border-color: rgba(88, 166, 255, 0.3) !important;
    transform: translateX(4px);
}

.activity-icon {
    flex-shrink: 0;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 16px;
    font-size: 16px;
}

.activity-icon i.critical {
    color: var(--danger-color);
    background: rgba(248, 81, 73, 0.1);
    padding: 12px;
    border-radius: 50%;
}

.activity-icon i.high {
    color: var(--warning-color);
    background: rgba(227, 179, 65, 0.1);
    padding: 12px;
    border-radius: 50%;
}

.activity-icon i.medium {
    color: var(--primary-color);
    background: rgba(88, 166, 255, 0.1);
    padding: 12px;
    border-radius: 50%;
}

.activity-icon i.low {
    color: var(--secondary-text-color);
    background: rgba(125, 133, 144, 0.1);
    padding: 12px;
    border-radius: 50%;
}

.activity-content {
    flex: 1;
    min-width: 0;
}

.activity-title {
    font-weight: 500;
    color: var(--primary-text-color);
    margin-bottom: 8px;
    font-size: 0.95em;
    line-height: 1.4;
}

.activity-meta {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}

.meta-item {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.85em;
    color: var(--secondary-text-color);
}

.meta-item i {
    font-size: 12px;
    opacity: 0.7;
}

.level-10, .level-11, .level-12, .level-13, .level-14, .level-15 {
    color: var(--danger-color) !important;
}

.level-7, .level-8, .level-9 {
    color: var(--warning-color) !important;
}

.level-4, .level-5, .level-6 {
    color: var(--primary-color) !important;
}

.activity-arrow {
    flex-shrink: 0;
    margin-left: 16px;
    color: var(--secondary-text-color);
    font-size: 14px;
    transition: all 0.2s ease;
}

.activity-item:hover .activity-arrow {
    color: var(--primary-color);
    transform: translateX(4px);
}

.empty-state {
    text-align: center;
    padding: 40px 20px;
    color: var(--secondary-text-color);
}

.empty-state i {
    font-size: 48px;
    color: var(--success-color);
    margin-bottom: 16px;
    display: block;
}

.empty-state p {
    margin: 0 0 8px 0;
    font-size: 1.1em;
    color: var(--primary-text-color);
}

.empty-state small {
    font-size: 0.9em;
    color: var(--secondary-text-color);
}

@media (max-width: 768px) {
    .activity-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    
    .activity-meta {
        flex-direction: column;
        gap: 8px;
    }
    
    .activity-item {
        padding: 12px;
    }
    
    .activity-icon {
        width: 36px;
        height: 36px;
        margin-right: 12px;
    }
}
```

**File: `app/static/css/manager.css`**
```css
.management-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-top: 30px;
}

.manager-list {
    animation: slideInLeft 0.6s ease;
    background-color: var(--surface-color) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    padding: 24px !important;
}

.add-manager-form {
    animation: slideInRight 0.6s ease;
    background-color: var(--surface-color) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    padding: 24px !important;
}

@keyframes slideInLeft {
    from {
        opacity: 0;
        transform: translateX(-30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes slideInRight {
    from {
        opacity: 0;
        transform: translateX(30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.manager-list h2,
.add-manager-form h2 {
    margin: 0 0 20px 0;
    color: var(--primary-text-color);
    font-size: 1.3em;
    display: flex;
    align-items: center;
    gap: 10px;
}

.manager-list h2::before {
    content: "🗄️";
    font-size: 1.2em;
}

.add-manager-form h2::before {
    content: "➕";
    font-size: 1.2em;
}

.manager-list ul {
    list-style: none !important;
    padding: 0 !important;
    margin: 0 !important;
}

.manager-list li {
    background: rgba(255, 255, 255, 0.02) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    padding: 16px !important;
    margin-bottom: 12px !important;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
    display: block !important;
    list-style: none !important;
}

.manager-list li::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 4px;
    height: 100%;
    background: var(--primary-color);
    transform: scaleY(0);
    transition: transform 0.3s ease;
}

.manager-list li:hover {
    background: rgba(88, 166, 255, 0.05) !important;
    border-color: rgba(88, 166, 255, 0.3) !important;
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.manager-list li:hover::before {
    transform: scaleY(1);
}

.manager-list li:last-child {
    margin-bottom: 0;
}

.manager-list strong {
    color: var(--primary-text-color);
    font-size: 1.1em;
    display: block;
    margin-bottom: 6px;
}

.manager-list li form {
    margin-top: 12px;
}

.manager-list li form input[type="submit"] {
    background: var(--danger-color);
    color: white;
    border: none;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.85em;
    transition: all 0.2s ease;
    opacity: 0.8;
}

.manager-list li form input[type="submit"]:hover {
    opacity: 1;
    transform: scale(1.05);
    background: #ff6b6b;
}

.add-manager-form form {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.add-manager-form form p {
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.add-manager-form label {
    color: var(--primary-text-color);
    font-weight: 500;
    font-size: 0.95em;
}

.add-manager-form input[type="text"],
.add-manager-form input[type="url"],
.add-manager-form input[type="password"] {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 12px 16px;
    color: var(--primary-text-color);
    font-size: 0.95em;
    transition: all 0.3s ease;
    outline: none;
}

.add-manager-form input[type="text"]:focus,
.add-manager-form input[type="url"]:focus,
.add-manager-form input[type="password"]:focus {
    border-color: var(--primary-color);
    background: rgba(88, 166, 255, 0.1);
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
    transform: translateY(-1px);
}

.add-manager-form input[type="submit"] {
    background: var(--primary-color);
    color: white;
    border: none;
    padding: 14px 24px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1em;
    font-weight: 500;
    transition: all 0.3s ease;
    margin-top: 10px;
    position: relative;
    overflow: hidden;
}

.add-manager-form input[type="submit"]::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 0;
    height: 0;
    background: rgba(255, 255, 255, 0.2);
    border-radius: 50%;
    transform: translate(-50%, -50%);
    transition: all 0.3s ease;
}

.add-manager-form input[type="submit"]:hover {
    background: #4a8fff;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(88, 166, 255, 0.3);
}

.add-manager-form input[type="submit"]:hover::before {
    width: 300px;
    height: 300px;
}

.add-manager-form input[type="submit"]:active {
    transform: translateY(0);
}

.flash-messages {
    margin: 20px 0;
}

.alert-success,
.alert-danger,
.alert-warning,
.alert-info {
    padding: 15px 20px;
    border-radius: 8px;
    margin-bottom: 15px;
    border-left: 4px solid;
    animation: slideInTop 0.5s ease;
    position: relative;
    overflow: hidden;
}

@keyframes slideInTop {
    from {
        opacity: 0;
        transform: translateY(-20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.alert-success {
    background: rgba(86, 211, 100, 0.1);
    color: var(--success-color);
    border-left-color: var(--success-color);
}

.alert-danger {
    background: rgba(248, 81, 73, 0.1);
    color: var(--danger-color);
    border-left-color: var(--danger-color);
}

.alert-warning {
    background: rgba(227, 179, 65, 0.1);
    color: var(--warning-color);
    border-left-color: var(--warning-color);
}

.alert-info {
    background: rgba(88, 166, 255, 0.1);
    color: var(--primary-color);
    border-left-color: var(--primary-color);
}

.manager-list p {
    color: var(--secondary-text-color);
    font-style: italic;
    text-align: center;
    padding: 40px 20px;
    background: rgba(255, 255, 255, 0.02);
    border: 2px dashed var(--border-color);
    border-radius: 8px;
    margin: 0;
}

@media (max-width: 768px) {
    .management-grid {
        grid-template-columns: 1fr;
        gap: 20px;
    }
    
    .manager-list,
    .add-manager-form {
        animation: fadeIn 0.6s ease;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .add-manager-form input[type="text"],
    .add-manager-form input[type="url"],
    .add-manager-form input[type="password"] {
        padding: 14px 16px;
        font-size: 16px; /* Prevents zoom on iOS */
    }
}

/* Loading animation for form submission */
.add-manager-form input[type="submit"]:disabled {
    background: var(--secondary-text-color);
    cursor: not-allowed;
    animation: pulse 1.5s infinite;
}

/* Page header with back button */
.page-header {
    position: relative;
    margin-bottom: 30px;
}

.header-actions {
    position: absolute;
    top: 0;
    right: 0;
}

.btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    text-decoration: none;
    font-size: 0.9em;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
}

.btn-back {
    background: rgba(255, 255, 255, 0.1);
    color: var(--secondary-text-color);
    border: 1px solid var(--border-color);
}

.btn-back:hover {
    background: rgba(255, 255, 255, 0.15);
    color: var(--primary-text-color);
    transform: translateX(-2px);
}

.btn-edit {
    background: var(--primary-color);
    color: white;
    font-size: 0.8em;
    padding: 6px 12px;
}

.btn-edit:hover {
    background: #4a8fff;
    transform: scale(1.05);
}

.btn-cancel {
    background: var(--secondary-text-color);
    color: white;
    font-size: 0.8em;
    padding: 6px 12px;
}

.btn-cancel:hover {
    background: #8a9199;
    transform: scale(1.05);
}

.btn-delete {
    background: var(--danger-color) !important;
    color: white !important;
    border: none !important;
    padding: 6px 12px !important;
    border-radius: 4px !important;
    cursor: pointer;
    font-size: 0.8em !important;
    transition: all 0.2s ease;
    opacity: 0.8;
}

.btn-delete:hover {
    opacity: 1 !important;
    transform: scale(1.05);
    background: #ff6b6b !important;
}

.btn-secondary {
    background: rgba(255, 255, 255, 0.1);
    color: var(--secondary-text-color);
    border: 1px solid var(--border-color);
    padding: 12px 20px;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    font-size: 0.95em;
}

.btn-secondary:hover {
    background: rgba(255, 255, 255, 0.15);
    color: var(--primary-text-color);
}

/* Manager list item improvements */
.manager-list li {
    display: flex !important;
    justify-content: space-between !important;
    align-items: flex-start !important;
    /* ...existing properties... */
}

.manager-list li.editing {
    border-color: var(--primary-color) !important;
    background: rgba(88, 166, 255, 0.1) !important;
}

.manager-info {
    flex: 1;
}

.manager-info strong {
    display: block;
    margin-bottom: 4px;
}

.manager-url {
    color: var(--secondary-text-color);
    font-size: 0.9em;
    font-family: monospace;
}

.manager-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-top: 8px;
}

/* Edit notice */
.edit-notice {
    background: rgba(88, 166, 255, 0.1);
    border: 1px solid rgba(88, 166, 255, 0.3);
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 20px;
    color: var(--primary-color);
    display: flex;
    align-items: center;
    gap: 8px;
}

/* Form actions */
.form-actions {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-top: 10px;
}

.form-actions p {
    margin: 0 !important;
    flex: 1;
}

/* Password field placeholder styling for edit mode */
.add-manager-form input[type="password"]::placeholder {
    font-style: italic;
    opacity: 0.7;
}

/* Mobile responsive updates */
@media (max-width: 768px) {
    .page-header {
        text-align: center;
    }
    
    .header-actions {
        position: static;
        margin-bottom: 20px;
    }
    
    .manager-list li {
        flex-direction: column !important;
        align-items: stretch !important;
    }
    
    .manager-actions {
        justify-content: space-between;
        margin-top: 12px;
    }
    
    .form-actions {
        flex-direction: column;
    }
    
    .form-actions .btn-secondary {
        width: 100%;
    }
}
```

**File: `app/static/css/style.css`**
```css
:root {
    --background-color: #0d1117;
    --surface-color: #161b22;
    --primary-text-color: #e6edf3;
    --secondary-text-color: #7d8590;
    --primary-color: #58a6ff;
    --border-color: #30363d;
    --danger-color: #f85149;
    --success-color: #56d364;
    --warning-color: #e3b341;
    --icon-size-sm: 12px;
    --icon-size-md: 16px;
    --icon-size-lg: 24px;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--background-color);
    color: var(--primary-text-color);
    line-height: 1.6;
    margin: 0;
}

.container {
    max-width: 1200px;
    margin: 40px auto;
    padding: 20px;
}

.dashboard-header {
    margin-bottom: 30px;
}

.dashboard-header h1 {
    margin: 0;
    font-size: 2em;
}

.dashboard-header .tagline {
    color: var(--secondary-text-color);
    margin-top: 5px;
}

.dashboard-header .header-actions {
    float: right;
}
.dashboard-header .header-actions .btn {
    background-color: var(--surface-color);
    border: 1px solid var(--border-color);
    color: var(--primary-text-color);
    padding: 8px 16px;
    border-radius: 6px;
    text-decoration: none;
    margin-left: 10px;
    transition: all 0.2s ease;
}
.dashboard-header .header-actions .btn:hover {
    background-color: #2c333e;
    border-color: var(--secondary-text-color);
}

.card {
    background-color: var(--surface-color);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 20px;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card h3 {
    margin: 0 0 5px 0;
    color: var(--secondary-text-color);
    font-size: 1em;
    font-weight: normal;
}

.stat-card .value {
    font-size: 2.2em;
    font-weight: 600;
    color: var(--primary-text-color);
}

.stat-card .status-protected { color: var(--success-color); }
.stat-card .status-error { color: var(--danger-color); }

.stat-card .meta {
    margin-top: 8px;
    font-size: 0.9em;
    color: var(--secondary-text-color);
}

.alert-danger {
    background-color: rgba(248, 81, 73, 0.1);
    color: var(--danger-color);
    border: 1px solid var(--danger-color);
    padding: 15px;
    border-radius: 6px;
    margin-bottom: 20px;
}
.alert-danger a {
    color: var(--primary-color);
    font-weight: bold;
    text-decoration: none;
}
.alert-danger a:hover {
    text-decoration: underline;
}

/* Link reset for activity items */
.activity-link,
.activity-link:visited,
.activity-link:hover,
.activity-link:focus,
.activity-link:active {
    color: inherit !important;
    text-decoration: none !important;
}

/* Force activity item styling */
.activity-feed .activity-item {
    background-color: #21262d !important;
    border: 1px solid #30363d !important;
    padding: 16px !important;
    margin-bottom: 12px !important;
    border-radius: 8px !important;
    display: flex !important;
}

/* Icon utilities */
.fi {
    line-height: 1;
}
```

</details>

### 5.2. Update HTML Templates

Now, update the HTML templates to use the new styles and data structures.

**File: `app/templates/layouts/base.html`**
```html
<!-- app/templates/layouts/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/manager.css') }}">

</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

**File: `app/templates/dashboard/index.html`**
This is a major update. We now display status cards and loop through the aggregated alerts, showing the source manager for each one.

```html
{% extends "layouts/base.html" %}

{% block content %}
    <!-- Include Flaticon CSS -->
    <link rel="stylesheet" href="https://cdn-uicons.flaticon.com/2.6.0/uicons-bold-rounded/css/uicons-bold-rounded.css">
    <link rel="stylesheet" href="https://cdn-uicons.flaticon.com/2.6.0/uicons-solid-rounded/css/uicons-solid-rounded.css">

    <header class="dashboard-header">
        <div class="header-actions">
            <a href="{{ url_for('managers.manage') }}" class="btn">Manage Indexers</a>
            <a href="{{ url_for('auth.logout') }}" class="btn">Sign Out</a>
        </div>
        <h1>LAMIS Dashboard</h1>
        <p class="tagline">Log Analysis and Monitoring System - Monitor and manage your security status</p>
    </header>

    {# Display any flashed error messages for manager connections #}
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                {% if category == 'danger' %}
                <div class="alert-{{ category }}">
                    {{ message }} <a href="{{ url_for('managers.manage') }}">Review configuration.</a>
                </div>
                {% endif %}
            {% endfor %}
        {% endif %}
    {% endwith %}

    <div class="stats-grid">
        {% set connected_managers = manager_statuses|selectattr(1, 'equalto', True)|list %}
        {% set total_managers = manager_statuses|length %}
        
        <div class="card stat-card">
            <h3>System Status</h3>
            {% if connected_managers|length == total_managers and total_managers > 0 %}
                <div class="value status-protected">Protected</div>
                <div class="meta">{{ connected_managers|length }} of {{ total_managers }} systems operational</div>
            {% else %}
                <div class="value status-error">Error</div>
                <div class="meta">{{ connected_managers|length }} of {{ total_managers }} systems operational</div>
            {% endif %}
        </div>

        {# Placeholder for other stat cards #}
        <div class="card stat-card">
            <h3>Detected Attacks</h3>
            <div class="value">...</div>
            <div class="meta">...</div>
        </div>
        <div class="card stat-card">
            <h3>Blocked Attacks</h3>
            <div class="value">...</div>
            <div class="meta">...</div>
        </div>
        <div class="card stat-card">
            <h3>Blocked IPs</h3>
            <div class="value">...</div>
            <div class="meta">...</div>
        </div>
    </div>

    <div class="activity-feed">
        <div class="activity-header">
            <h2><i class="fi fi-br-time-past"></i> Recent Activity</h2>
            <span class="activity-count">{{ alerts|length }} recent alerts</span>
        </div>
        {% if alerts %}
            <div class="activity-list">
                {% for alert in alerts %}
                    <a href="{{ url_for('alerts.detail', manager_id=alert._source_manager_id, index_name=alert._index, alert_id=alert._id) }}" class="activity-link">
                        <div class="activity-item">
                            <div class="activity-icon">
                                {% if alert._source.rule.level >= 10 %}
                                    <i class="fi fi-sr-shield-exclamation critical"></i>
                                {% elif alert._source.rule.level >= 7 %}
                                    <i class="fi fi-sr-triangle-warning high"></i>
                                {% elif alert._source.rule.level >= 4 %}
                                    <i class="fi fi-sr-info medium"></i>
                                {% else %}
                                    <i class="fi fi-sr-eye low"></i>
                                {% endif %}
                            </div>
                            <div class="activity-content">
                                <div class="activity-title">{{ alert._source.rule.description }}</div>
                                <div class="activity-meta">
                                    <span class="meta-item">
                                        <i class="fi fi-br-database"></i>
                                        {{ alert._source_manager_name }}
                                    </span>
                                    <span class="meta-item">
                                        <i class="fi fi-br-clock"></i>
                                        {{ alert._source.timestamp }}
                                    </span>
                                    <span class="meta-item level-{{ alert._source.rule.level }}">
                                        <i class="fi fi-br-target"></i>
                                        Level {{ alert._source.rule.level }}
                                    </span>
                                </div>
                            </div>
                            <div class="activity-arrow">
                                <i class="fi fi-br-angle-right"></i>
                            </div>
                        </div>
                    </a>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty-state">
                <i class="fi fi-br-shield-check"></i>
                <p>No recent alerts found from any active managers.</p>
                <small>Your systems are running smoothly!</small>
            </div>
        {% endif %}
    </div>
{% endblock %}
```
**Code Explanation:**
*   **`url_for('alerts.detail', manager_id=alert._source_manager_id, ...)`**: This is where we use the context we injected in the service layer. We pass the `manager_id` to the URL, ensuring the link goes to the correct detail page for that specific alert on that specific manager.
*   **`{{ alert._source_manager_name }}`**: We can now display the name of the manager the alert came from, providing crucial context to the user.

Finally, update the authentication templates to use the new CSS.

<details>
<summary>Click to see <code>auth/login.html</code> and <code>auth/setup.html</code></summary>

**File: `app/templates/auth/login.html`**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS - Sign In</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/auth.css') }}">
</head>
<body>
    <div class="auth-container">
        <h1>Sign In to LAMIS</h1>
        
        <div class="flash-messages">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        </div>

        <form action="" method="post" novalidate>
            {{ form.hidden_tag() }}
            <div class="form-group">
                {{ form.username.label }}
                {{ form.username(class="form-control") }}
                {% for error in form.username.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.password.label }}
                {{ form.password(class="form-control") }}
                {% for error in form.password.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.submit(class="btn-submit") }}
            </div>
        </form>
    </div>
</body>
</html>
```

**File: `app/templates/auth/setup.html`**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAMIS - Initial Setup</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/auth.css') }}">
</head>
<body>
    <div class="auth-container">
        <h1>Initial LAMIS Setup</h1>
        <p class="subtitle">Create the primary administrator account.</p>

        <form action="" method="post" novalidate>
            {{ form.hidden_tag() }}
            <div class="form-group">
                {{ form.username.label }}
                {{ form.username(class="form-control") }}
                {% for error in form.username.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.password.label }}
                {{ form.password(class="form-control") }}
                {% for error in form.password.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.confirm_password.label }}
                {{ form.confirm_password(class="form-control") }}
                {% for error in form.confirm_password.errors %}<p class="error">{{ error }}</p>{% endfor %}
            </div>
            <div class="form-group">
                {{ form.submit(class="btn-submit") }}
            </div>
        </form>
    </div>
</body>
</html>
```
</details>

</details>

---

## Conclusion and Final Checks

Congratulations! You have successfully completed a major refactor of the LAMIS application.

You have transformed a rigid, single-purpose tool into a flexible, scalable, and more secure platform. You've implemented a robust system for managing multiple API connections, complete with encrypted credential storage, a clean user interface, and performant, concurrent data fetching.

**To run the new application:**
1.  Ensure your Docker container for PostgreSQL is running.
2.  If this is a fresh database, remember to run `flask db upgrade` to create all the tables.
3.  Run `flask run`.
4.  Navigate to the application in your browser. You will be guided through the new setup process: create an admin, then add your first Wazuh manager.

This new architecture is a solid foundation upon which we can build many more powerful features. You have done excellent work.
