## LAMIS Refactor Tutorial: Integrating OPNsense IP Blocking

This tutorial will walk you through the process of transforming the old LAMIS application into a more robust, modular, and feature-rich version.

### Part 0: Prerequisites & Environment Setup

Before we write a single line of Python, we need to configure our environment. This feature requires connecting to two external services: our **PostgreSQL database** and our **OPNsense firewall**.

<details>
<summary><strong>Step 0.1: Prepare Your OPNsense Firewall</strong></summary>

For LAMIS to block IPs, it needs three things from OPNsense:
1.  An API Key and Secret for authentication.
2.  The name of a Firewall Alias where it will store the list of blocked IPs.
3.  The URL to your OPNsense instance.

#### **Getting an API Key and Secret**

1.  Log in to your OPNsense firewall (e.g., `https://192.168.111.1:8443/`).
2.  Navigate to **System &rarr; Access &rarr; Users**.
3.  Find the user you want to generate API keys for (or create a new, dedicated user for LAMIS).
4.  Click the "plus" (+) button under the `API-Keys` section for that user.
5.  OPNsense will generate a new Key and Secret. **Copy these immediately.** The Secret is only shown once.

    *(Here you would include a screenshot of the OPNsense UI showing the API key generation)*
    ![OPNsense API Key Generation](API.png)

#### **Creating a Firewall Alias**

An Alias is just a named list. We will create an Alias of type "Host(s)" that will hold all the IPs we want to block.

1.  In OPNsense, navigate to **Firewall &rarr; Aliases**.
2.  Click the "plus" (+) button to add a new alias.
3.  Configure it as follows:
    *   **Name:** Give it a descriptive name, like `LAMIS_Blocklist`. **You must remember this exact name.**
    *   **Type:** `Host(s)`
    *   **Content:** You can leave this blank for now. LAMIS will populate it.
    *   **Description:** "IPs blocked by the LAMIS application."
4.  Save and Apply changes.

#### **Create a Firewall Rule (NANTI AJA NANTI KEBLOCK KITA SEMUA TAPI READ TO UNDERSTAND)**

Finally, you need a firewall rule that uses this alias to actually block traffic. A common place to put this is on your WAN interface.

1.  Navigate to **Firewall &rarr; Rules &rarr; WAN**.
2.  Create a new rule:
    *   **Action:** `Block`
    *   **Interface:** `WAN`
    *   **Direction:** `in`
    *   **Source:** Choose your new alias (`LAMIS_Blocklist`) from the list.
    *   **Destination:** `Any`
    *   **Description:** "Block incoming traffic from LAMIS blocklist".
3.  Save and Apply changes. Make sure this rule is positioned correctly in your ruleset (usually near the top).

</details>

<details>
<summary><strong>Step 0.2: Update Your Environment File (`.env`)</strong></summary>

Now that you have your OPNsense credentials, you must store them securely as environment variables. **Never hardcode secrets in your code.**

Open your `.env` file and add the new variables for OPNsense.

```dotenv
# .env

# --- Existing Variables ---
SECRET_KEY='this-is-a-secret-please-change-it'
DATABASE_URL='postgresql://postgres:password@localhost:5432/orm_db'
ENCRYPTION_KEY='A7tR3tgrehdheqAYbjR-Ij1fw_a68OSdcSIk1eIxwtc='

# --- NEW: OPNsense Firewall Integration ---
# The base URL of your OPNsense firewall
OPNSENSE_URL='https://192.168.111.1:8443'

# The API Key generated in OPNsense (System -> Access -> Users -> API Keys)
OPNSENSE_API_KEY='YOUR_API_KEY_HERE'

# The API Secret corresponding to the key
OPNSENSE_API_SECRET='YOUR_API_SECRET_HERE'

# The EXACT name of the IP Alias you created in OPNsense to hold the blocked IPs
OPNSENSE_ALIAS_NAME='LAMIS_Blocklist'
```

**Why do we do this?**
The `.env` file is typically included in your project's `.gitignore` file, meaning it's never committed to version control. This prevents your secret keys from being exposed in your repository. The `python-dotenv` library loads these variables into the application's environment at runtime, where our `config.py` can access them.

</details>

<details>
<summary><strong>Step 0.3: Update the Configuration File (`config.py`)</strong></summary>

Next, we need to teach our Flask application how to read these new variables from the environment.

Update `config.py` to load the OPNsense settings.

```python
# config.py

import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__name__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    """
    Application configuration class.
    Loads settings from environment variables for security and flexibility.
    """

    # Flask Core
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Credential Encryption
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

    # --- NEW: OPNsense Firewall Integration ---
    OPNSENSE_URL = os.environ.get("OPNSENSE_URL")
    OPNSENSE_API_KEY = os.environ.get("OPNSENSE_API_KEY")
    OPNSENSE_API_SECRET = os.environ.get("OPNSENSE_API_SECRET")
    OPNSENSE_ALIAS_NAME = os.environ.get("OPNSENSE_ALIAS_NAME")

```

**Explanation:**
*   `os.environ.get("VAR_NAME")`: This is the standard Python way to access an environment variable. Using `.get()` is safer than `[]` because it returns `None` if the variable isn't found, preventing a crash.
*   By adding these here, any part of our Flask application can access them via `current_app.config['OPNSENSE_URL']`. This centralizes configuration management.

</details>

***

### Part 1: The Database Layer - Our Source of Truth

To block an IP, we need to store it somewhere. While the OPNsense alias is the *enforcement point*, our application's database will be the **source of truth**. This lets us track *why* and *when* an IP was blocked, and manage it even if OPNsense is temporarily offline.

<details>
<summary><strong>Step 1.1: Create the Database Model (`app/models/ip_block.py`)</strong></summary>

A "model" is a Python class that represents a table in our database. We'll use SQLAlchemy to define the structure of our new `blocked_ips` table.

Create a new file: `app/models/ip_block.py`

```python
# app/models/ip_block.py

from datetime import datetime
from typing import Optional

from app.models import db


class BlockedIP(db.Model):
    """
    Represents a single IP address that has been blocked.
    This table is the application's source of truth for blocked entities.
    """

    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    blocked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # blocked_by = db.relationship('User')

    def __repr__(self) -> str:
        return f"<BlockedIP {self.ip_address}>"

    @staticmethod
    def is_blocked(ip_address: str) -> bool:
        """
        A quick, efficient check to see if an IP address exists in the table.
        """
        return db.session.query(
            BlockedIP.query.filter_by(ip_address=ip_address).exists()
        ).scalar()

```

**Code Explanation:**
*   `class BlockedIP(db.Model)`: This class inherits from `db.Model`, which is the base class for all models in Flask-SQLAlchemy.
*   `__tablename__ = "blocked_ips"`: Explicitly names the table in our database.
*   `db.Column(...)`: Each attribute of this type defines a column in the table.
    *   `db.Integer, primary_key=True`: The unique ID for each row.
    *   `db.String(45)`: A string column. We use 45 characters to accommodate IPv6 addresses.
    *   `unique=True`: Enforces that no two rows can have the same IP address.
    *   `index=True`: Tells the database to create an index on this column, making lookups by IP address much faster.
    *   `db.DateTime, default=datetime.utcnow`: Stores the timestamp of when the block occurred. `default=datetime.utcnow` automatically sets the current time.
*   `@staticmethod`: This decorator means the `is_blocked` method belongs to the class itself, not an instance of the class. You can call it directly: `BlockedIP.is_blocked("1.2.3.4")`.
*   `.exists()`.`scalar()`: This is a highly efficient way to check for existence. Instead of fetching the whole row, it asks the database for a simple True/False, which is much faster.

</details>

<details>
<summary><strong>Step 1.2: Register the Model & Generate a Migration</strong></summary>

Flask-Migrate, our database version control tool, needs to know that this new model exists.

#### **Register the Model**
First, import the new model in `app/__init__.py`. This ensures it's registered with SQLAlchemy when the app starts.

```python
# app/__init__.py
# ... (other imports)
from app.models.wazuh import WazuhManager

# NEW: Import the new BlockedIP model so Flask-Migrate can see it
from app.models.ip_block import BlockedIP
import logging
# ... (rest of the file)
```

#### **Generate the Migration Script**
Now, we can ask Flask-Migrate to compare our models with the current database state and generate a script to bridge the gap.

In your terminal, run:
```bash
flask db migrate -m "Add BlockedIP table"
```

This command will create a new file in `migrations/versions/`. It will have a name like `3efc8f9f0385_add_blockedip_table.py`. This file contains the Python code to create our new table.

```python
# migrations/versions/3efc8f9f0385_add_blockedip_table.py

"""Add BlockedIP table

Revision ID: 3efc8f9f0385
Revises: 427d82c6e0ac # This points to the previous migration
Create Date: 2025-07-11 09:11:04.702232

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3efc8f9f0385'
down_revision = '427d82c6e0ac'
branch_labels = None
depends_on = None


def upgrade():
    # This function defines what happens when we 'upgrade' the database
    op.create_table('blocked_ips',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=True),
        sa.Column('blocked_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('blocked_ips', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_blocked_ips_ip_address'), ['ip_address'], unique=True)


def downgrade():
    # This function defines the reverse operation, to 'downgrade' the database
    with op.batch_alter_table('blocked_ips', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_blocked_ips_ip_address'))

    op.drop_table('blocked_ips')
```
**Why do we need migrations?**
They provide a clear, version-controlled history of your database schema. Anyone on the team can check out the code, run the migrations, and have an identical database structure. It's repeatable and reliable.

</details>

<details>
<summary><strong>Step 1.3: Apply the Migration to the Database</strong></summary>

The previous step only created the *script*. This step will execute that script against your database.

In your terminal, run:
```bash
flask db upgrade
```

You should see output indicating that the migration is being applied. Now, if you inspect your PostgreSQL database, you will see the new `blocked_ips` table!

</details>

***

### Part 2: Building the IP Blocking Module

Now for the core logic. We will create a new, self-contained module for everything related to IP blocking. This is the **Anti-Spaghetti Mandate** in action.

<details>
<summary><strong>Step 2.1: Create the Module Structure</strong></summary>

Create a new directory `app/ip_blocking/`. Inside it, create four empty files:
```
app/
└── ip_blocking/
    ├── __init__.py         # Makes this a Python package
    ├── forms.py            # For our WTForms
    ├── routes.py           # For our Flask routes/endpoints
    └── services.py         # For our business logic
```

</details>

<details>
<summary><strong>Step 2.2: Create the Forms (`app/ip_blocking/forms.py`)</strong></summary>

Forms are our first line of defense. They provide server-side validation and CSRF (Cross-Site Request Forgery) protection automatically.

Populate `app/ip_blocking/forms.py`:
```python
# app/ip_blocking/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, SubmitField
from wtforms.validators import DataRequired, IPAddress


class BlockIPForm(FlaskForm):
    """Form for the action of blocking an IP."""

    ip_address = HiddenField("IP Address", validators=[DataRequired(), IPAddress()])
    reason = HiddenField("Reason")
    submit = SubmitField("Block IP")


class UnblockIPForm(FlaskForm):
    """Form for the action of unblocking an IP."""

    ip_address = HiddenField("IP Address", validators=[DataRequired(), IPAddress()])
    submit = SubmitField("Unblock")
```

**Code Explanation:**
*   `HiddenField`: We use hidden fields because the user won't be typing the IP address into a text box. Instead, they'll click a "Block" button next to an alert. We will use JavaScript to populate these hidden fields before submitting the form.
*   `validators`: This is the crucial part.
    *   `DataRequired()`: Ensures the field is not empty.
    *   `IPAddress()`: A built-in validator that ensures the submitted value is a valid IPv4 or IPv6 address. This prevents us from trying to block invalid data.

</details>

<details>
<summary><strong>Step 2.3: Write the Service Layer (`app/ip_blocking/services.py`)</strong></summary>

This is the brain of our new feature. The "service layer" contains all the business logic, separate from the web routes. This makes the logic reusable and easier to test.

Populate `app/ip_blocking/services.py`:
```python
# app/ip_blocking/services.py

import ipaddress
import requests
from typing import List, Tuple, Optional

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.models import db
from app.models.ip_block import BlockedIP


def get_all_blocked_ips():
    """Fetches all blocked IPs from the database, ordered by most recent."""
    return BlockedIP.query.order_by(BlockedIP.blocked_at.desc())


def get_blocked_ips_as_set() -> set:
    """
    Fetches all blocked IP addresses as a set for efficient lookups.
    This is much faster than querying the DB repeatedly in a loop.
    """
    ips = db.session.query(BlockedIP.ip_address).all()
    return {ip[0] for ip in ips}


def block_ip(ip_to_block: str, reason: str) -> Tuple[bool, str]:
    """
    Main service function to block an IP address.
    Orchestrates validation, database insertion, and the firewall API call.
    """
    # 1. 🔐 Security: Validate the input is a valid IP address.
    try:
        ipaddress.ip_address(ip_to_block)
    except ValueError:
        msg = f"Invalid IP address format: {ip_to_block}"
        current_app.logger.warning(msg)
        return False, msg

    # 2. 🏛️ Logic: Check if already blocked to avoid duplicate work.
    if BlockedIP.is_blocked(ip_to_block):
        msg = f"IP address {ip_to_block} is already in the blocklist."
        current_app.logger.info(msg)
        return True, msg

    # 3. 💾 Database: Add to our local database first.
    new_block = BlockedIP(ip_address=ip_to_block, reason=reason)
    db.session.add(new_block)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        msg = f"IP address {ip_to_block} was already in the blocklist (race condition)."
        return True, msg
    except Exception as e:
        db.session.rollback()
        msg = f"Database error while blocking {ip_to_block}: {e}"
        return False, msg

    # 4. 🔥 Firewall: Update the OPNsense alias.
    success, message = _update_opnsense_alias()
    if not success:
        # If the firewall update fails, we must roll back the database change
        current_app.logger.error(f"Rolling back database entry for {ip_to_block}.")
        db.session.delete(new_block)
        db.session.commit()
        return False, message

    return True, f"Successfully blocked {ip_to_block} and updated firewall."


def unblock_ip(ip_to_unblock: str) -> Tuple[bool, str]:
    """Main service function to unblock an IP address."""
    record = BlockedIP.query.filter_by(ip_address=ip_to_unblock).first()
    if not record:
        msg = f"IP address {ip_to_unblock} is not in the blocklist."
        return False, msg

    # Delete from our DB first.
    db.session.delete(record)
    db.session.commit()

    # Update OPNsense.
    success, message = _update_opnsense_alias()
    if not success:
        # This is a problem state: IP is unblocked in LAMIS but not on the firewall.
        current_app.logger.error(f"Firewall update failed after unblocking {ip_to_unblock}.")
        return False, f"{message}. The IP is unblocked in LAMIS, but the firewall update failed."

    return True, f"Successfully unblocked {ip_to_unblock}."


def _get_alias_uuid(alias_name: str, auth: tuple, base_url: str) -> Optional[str]:
    """Fetches the UUID of an alias by its name."""
    try:
        response = requests.get(f"{base_url}/api/firewall/alias/get", auth=auth, verify=False, timeout=10)
        response.raise_for_status()
        aliases = response.json().get("alias", {}).get("aliases", {}).get("alias", {})
        for uuid, details in aliases.items():
            if details.get("name") == alias_name:
                return uuid
        return None
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching alias UUID: {e}")
        return None


def _update_opnsense_alias() -> Tuple[bool, str]:
    """
    Private helper to communicate with the OPNsense API.
    It updates a pre-defined alias with the full list of blocked IPs.
    """
    config = current_app.config
    base_url, api_key, api_secret, alias_name = (
        config.get("OPNSENSE_URL"),
        config.get("OPNSENSE_API_KEY"),
        config.get("OPNSENSE_API_SECRET"),
        config.get("OPNSENSE_ALIAS_NAME"),
    )

    if not all([base_url, api_key, api_secret, alias_name]):
        msg = "OPNsense configuration is incomplete in .env file."
        return False, msg

    auth = (api_key, api_secret)
    alias_uuid = _get_alias_uuid(alias_name, auth, base_url)
    if not alias_uuid:
        msg = f"Could not find UUID for alias '{alias_name}'."
        return False, msg

    content = "\n".join(get_blocked_ips_as_set())
    api_url = f"{base_url}/api/firewall/alias/setItem/{alias_uuid}"
    payload = {"alias": {"content": content, "enabled": "1", "name": alias_name}}

    try:
        response = requests.post(api_url, auth=auth, json=payload, verify=False, timeout=10)
        response.raise_for_status()
        if response.json().get("result") == "saved":
            reconfigure_url = f"{base_url}/api/firewall/alias/reconfigure"
            reconfigure_response = requests.post(reconfigure_url, auth=auth, json={}, verify=False, timeout=15)
            reconfigure_response.raise_for_status()
            if reconfigure_response.json().get("status") == "ok":
                return True, "Firewall alias updated successfully."
            else:
                return False, "Failed to apply changes on OPNsense."
        else:
            return False, f"OPNsense API reported failure: {response.text}"
    except requests.exceptions.RequestException as e:
        msg = f"Network error communicating with OPNsense: {e}"
        return False, msg
```
*Note: I have simplified the code slightly from the `after.txt` version for clarity in this tutorial, removing some redundant logging and payload fields. The core logic is identical.*

**Code Explanation:**
*   `get_blocked_ips_as_set()`: This is a performance optimization. Checking `ip in my_set` is vastly faster than `ip in my_list`, especially for large lists. The dashboard will use this for quick UI checks. The `{ip[0] for ip in ips}` is a "set comprehension," a concise way to build a set.
*   `block_ip()`: This is our transaction script.
    1.  It validates the IP with the `ipaddress` library. This is a redundant check (WTForms already did it), but it's good practice for service layers to be self-contained and not trust their inputs.
    2.  It adds the IP to our database.
    3.  It calls `_update_opnsense_alias()` to sync the change to the firewall.
    4.  **CRITICAL**: If the firewall update fails, it *rolls back* the database change (`db.session.delete(new_block)`). This keeps our application state consistent with the firewall state.
*   `_update_opnsense_alias()`: This is the I/O heavy function.
    1.  It fetches all necessary config from `current_app.config`.
    2.  It calls a helper `_get_alias_uuid` to find the unique ID for our alias by its name. APIs often work with UUIDs, not names.
    3.  It fetches the *entire* list of blocked IPs from our database and joins them with newlines (`\n`). OPNsense expects the full list every time.
    4.  It makes two API calls: one to `setItem` to update the alias content, and a second to `reconfigure` to apply the changes.

</details>

<details>
<summary><strong>Step 2.4: Create the Routes (`app/ip_blocking/routes.py`)</strong></summary>

Routes are the "glue" that connect incoming web requests to our service logic. They should be "thin," meaning they do minimal work themselves and delegate the heavy lifting to the service layer.

Populate `app/ip_blocking/routes.py`:
```python
# app/ip_blocking/routes.py

from flask import (
    Blueprint, render_template, flash, redirect, url_for, request
)
from flask_login import login_required

from app.ip_blocking.forms import BlockIPForm, UnblockIPForm
from app.ip_blocking.services import (
    get_all_blocked_ips, block_ip, unblock_ip
)

bp = Blueprint("ip_blocking", __name__, url_prefix="/blocking")


@bp.route("/")
@login_required
def manage():
    """Displays the main IP blocking management page."""
    page = request.args.get("page", 1, type=int)
    blocked_ips_paginated = get_all_blocked_ips().paginate(
        page=page, per_page=20, error_out=False
    )
    unblock_form = UnblockIPForm()
    return render_template(
        "ip_blocking/manage.html",
        pagination=blocked_ips_paginated,
        unblock_form=unblock_form,
    )


@bp.route("/block", methods=["POST"])
@login_required
def block():
    """Handles the POST request to block an IP."""
    form = BlockIPForm()
    if form.validate_on_submit():
        success, message = block_ip(
            ip_to_block=form.ip_address.data,
            reason=form.reason.data
        )
        if success:
            flash(message, "success")
        else:
            flash(message, "danger")
    else:
        flash(f"Invalid data received for blocking request. Errors: {form.errors}", "danger")
    
    return redirect(request.referrer or url_for("dashboard.index"))


@bp.route("/unblock", methods=["POST"])
@login_required
def unblock():
    """Handles the POST request to unblock an IP."""
    form = UnblockIPForm()
    if form.validate_on_submit():
        success, message = unblock_ip(ip_to_unblock=form.ip_address.data)
        if success:
            flash(message, "success")
        else:
            flash(message, "danger")
    else:
        flash(f"Invalid data received for unblocking request. Errors: {form.errors}", "danger")

    return redirect(url_for("ip_blocking.manage"))
```
**Code Explanation:**
*   `bp = Blueprint(...)`: We define a Blueprint. All routes here will be prefixed with `/blocking`.
*   `@login_required`: A decorator from Flask-Login that ensures only authenticated users can access these routes.
*   `manage()`: This route handles the main management page. It gets the list of blocked IPs from the service and uses `.paginate()` to prepare the data for display across multiple pages.
*   `block()` and `unblock()`: These routes only accept `POST` requests, which is a security best practice for actions that change data.
    *   `form = BlockIPForm()`: It instantiates the form. Flask-WTF automatically populates it with the submitted data.
    *   `form.validate_on_submit()`: This is magic. It checks if the request is a `POST` and if all the validators on the form fields pass. It also checks the CSRF token.
    *   `flash(message, category)`: This stores a message that will be displayed to the user on the next page they visit. It's how we provide feedback like "IP blocked successfully."
    *   `redirect(request.referrer ...)`: This sends the user back to the page they came from (e.g., the dashboard), which is a great user experience.

</details>

<details>
<summary><strong>Step 2.5: Register the Blueprint (`app/__init__.py`)</strong></summary>

Finally, we tell our main application factory that this new blueprint exists.

Update `app/__init__.py`:
```python
# app/__init__.py

# ... (at the top with other imports)
from app.models.ip_block import BlockedIP
import logging

login_manager = LoginManager()
migrate = Migrate()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    # ... (db, migrate, login_manager inits)

    with app.app_context():
        from .auth import routes as auth_routes
        from .dashboard import routes as dashboard_routes
        from .alerts import routes as alert_routes
        from .managers import routes as manager_routes

        # NEW: Import and register the ip_blocking blueprint
        from .ip_blocking import routes as ip_blocking_routes

        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(dashboard_routes.bp)
        app.register_blueprint(alert_routes.bp)
        app.register_blueprint(manager_routes.bp)
        app.register_blueprint(ip_blocking_routes.bp)

        # ... (rest of the file)
```
Now, Flask is aware of the `/blocking` URLs and will direct requests to our new `ip_blocking/routes.py` file.

</details>

***

### Part 3: Integrating the Feature into the UI

The backend is complete. Now we need to build the frontend so users can interact with it. This involves a major layout overhaul and significant updates to the dashboard.

<details>
<summary><strong>Step 3.1: A New Application Layout (`app/templates/layouts/base.html`)</strong></summary>

A good application needs a consistent and professional layout. We are moving from a very basic page to a modern sidebar-based design.

First, **delete the old `app/templates/layouts/base.html`** and replace it with this new content:

```html
<!-- app/templates/layouts/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block page_title %}LAMIS Dashboard{% endblock %}</title>
    <!-- Icon Library -->
    <link rel="stylesheet" href="https://cdn-uicons.flaticon.com/2.6.0/uicons-solid-rounded/css/uicons-solid-rounded.css">
    <link rel="stylesheet" href="https://cdn-uicons.flaticon.com/2.6.0/uicons-bold-rounded/css/uicons-bold-rounded.css">
    
    <!-- Core and Component Stylesheets -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/layout.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/manager.css') }}">
</head>
<body>
    <div class="app-wrapper">
        <aside class="sidebar">
            <div class="sidebar-header">
                <i class="fi fi-sr-shield-check logo-icon"></i>
                <div class="logo-text">
                    <h1>LAMIS</h1>
                    <p>Log Analysis & Monitoring</p>
                </div>
            </div>

            <nav class="sidebar-nav">
                <ul>
                    <li>
                        <a href="{{ url_for('dashboard.index') }}" class="{{ 'active' if request.blueprint == 'dashboard' else '' }}">
                            <i class="fi fi-sr-dashboard nav-icon"></i> Dashboard
                        </a>
                    </li>
                    <li>
                        <a href="{{ url_for('ip_blocking.manage') }}" class="{{ 'active' if request.blueprint == 'ip_blocking' else '' }}">
                            <i class="fi fi-sr-lock nav-icon"></i> IP Blocking
                        </a>
                    </li>
                    <li>
                        <a href="{{ url_for('managers.manage') }}" class="{{ 'active' if request.blueprint == 'managers' else '' }}">
                            <i class="fi fi-sr-database nav-icon"></i> Manage Indexers
                        </a>
                    </li>
                </ul>
            </nav>

            <div class="sidebar-footer">
                <a href="{{ url_for('auth.logout') }}">
                    <i class="fi fi-sr-exit nav-icon"></i> Sign Out
                </a>
            </div>
        </aside>

        <main class="main-content">
            <div class="content-container">
                {% block content %}{% endblock %}
            </div>
        </main>
    </div>
    {% block scripts %}{% endblock %}
</body>
</html>
```
**Code Explanation:**
*   `{% extends "layouts/base.html" %}`: All other pages will now inherit this structure.
*   `{% block content %}{% endblock %}`: This is the placeholder where the content of child templates will be injected.
*   `{% block scripts %}{% endblock %}`: A new block for page-specific JavaScript.
*   `url_for('static', filename='...')`: The correct way to link to CSS/JS files.
*   `class="{{ 'active' if request.blueprint == '...' else '' }}"`: This is clever Jinja2 logic. It checks which blueprint the current page belongs to and adds the `active` class to the corresponding sidebar link, highlighting it for the user.
*   We've added a new navigation link for "IP Blocking" that points to `ip_blocking.manage`.

</details>

<details>
<summary><strong>Step 3.2: Create the IP Blocking Management Page (`app/templates/ip_blocking/manage.html`)</strong></summary>

This is the UI for the `manage` route we created earlier. It will list all blocked IPs and allow unblocking.

Create the new file `app/templates/ip_blocking/manage.html`:

```html
<!-- app/templates/ip_blocking/manage.html -->
{% extends "layouts/base.html" %}

{% block page_title %}IP Blocking Management{% endblock %}

{% block content %}
    <div class="page-header">
        <h1><i class="fi fi-sr-lock"></i> IP Blocking Management</h1>
        <p>View all IPs currently being blocked by LAMIS via the OPNsense firewall.</p>
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

    <div class="card">
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Reason for Block</th>
                        <th>Blocked At (UTC)</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% if pagination.items %}
                        {% for ip in pagination.items %}
                        <tr>
                            <td><code class="ip-address">{{ ip.ip_address }}</code></td>
                            <td>{{ ip.reason or 'N/A' }}</td>
                            <td>{{ ip.blocked_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                            <td>
                                <form action="{{ url_for('ip_blocking.unblock') }}" method="post" class="unblock-form">
                                    {{ unblock_form.hidden_tag() }}
                                    {{ unblock_form.ip_address }}
                                    <button type="submit" class="btn btn-unblock" data-ip="{{ ip.ip_address }}">Unblock</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    {% else %}
                        <tr>
                            <td colspan="4" class="empty-state">
                                <i class="fi fi-br-shield-check"></i>
                                <p>No IPs are currently blocked.</p>
                            </td>
                        </tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
        
        {% if pagination.pages > 1 %}
        <div class="pagination">
            <a href="{{ url_for('ip_blocking.manage', page=pagination.prev_num) if pagination.has_prev else '#' }}" class="btn-page {% if not pagination.has_prev %}disabled{% endif %}">« Previous</a>
            <span class="page-info">Page {{ pagination.page }} of {{ pagination.pages }}</span>
            <a href="{{ url_for('ip_blocking.manage', page=pagination.next_num) if pagination.has_next else '#' }}" class="btn-page {% if not pagination.has_next %}disabled{% endif %}">Next »</a>
        </div>
        {% endif %}
    </div>
{% endblock %}

{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded', function() {
    const unblockForms = document.querySelectorAll('.unblock-form');
    unblockForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            const button = event.target.querySelector('.btn-unblock');
            const ip = button.dataset.ip;
            event.target.querySelector('input[name="ip_address"]').value = ip;
        });
    });
});
</script>
{% endblock %}
```
**Code Explanation:**
*   `pagination.items`: We loop through the items for the current page provided by the pagination object from our route.
*   `unblock_form.hidden_tag()`: Renders the CSRF token, crucial for security.
*   `data-ip="{{ ip.ip_address }}"`: We store the IP address in a `data-*` attribute on the button itself.
*   **JavaScript Block**: This is a key pattern. When a form is submitted, the script intercepts it, reads the `data-ip` from the button that was clicked, and sets the value of the hidden `ip_address` input field. This is how we pass the correct IP to the backend.

</details>

<details>
<summary><strong>Step 3.3: Upgrade the Dashboard (`app/templates/dashboard/index.html`)</strong></summary>

This is where the magic happens for the user. We will modify the dashboard to show block buttons and status.

Replace the content of `app/templates/dashboard/index.html` with the following:

```html
{% extends "layouts/base.html" %}

{% block page_title %}Dashboard{% endblock %}

{% block content %}
    <header class="page-header">
        <h1><i class="fi fi-sr-dashboard"></i> LAMIS Dashboard</h1>
        <p class="tagline">Log Analysis and Monitoring System - Monitor and manage your security status</p>
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="alert-{{ category }}">
                    {{ message }} 
                    {% if 'Connection Error' in message %}
                        <a href="{{ url_for('managers.manage') }}">Review configuration.</a>
                    {% endif %}
                </div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <div class="stats-grid">
        {% set connected_managers = manager_statuses|selectattr(1, 'equalto', True)|list %}
        {% set total_managers = manager_statuses|length %}
        
        <div class="card stat-card">
            <h3>System Status</h3>
            {% if total_managers > 0 and connected_managers|length == total_managers %}
                <div class="value status-protected">Protected</div>
            {% else %}
                <div class="value status-error">Error</div>
            {% endif %}
            <div class="meta">{{ connected_managers|length }} of {{ total_managers }} systems operational</div>
        </div>

        <div class="card stat-card">
            <h3>Blocked IPs</h3>
            <div class="value">{{ blocked_ips_set|length }}</div>
            <div class="meta">Total IPs in blocklist</div>
        </div>
        <div class="card stat-card">
            <h3>Recent Alerts</h3>
            <div class="value">{{ alerts|length }}</div>
            <div class="meta">In the last fetch</div>
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
                    {% set src_ip = alert._source.data.srcip if alert._source.data and 'srcip' in alert._source.data else None %}
                    {% set is_blocked = src_ip and src_ip in blocked_ips_set %}

                    <div class="activity-item-wrapper">
                        <a href="{{ url_for('alerts.detail', manager_id=alert._source_manager_id, index_name=alert._index, alert_id=alert._id) }}" class="activity-link">
                            <div class="activity-item {% if is_blocked %}is-blocked{% endif %}">
                                <!-- ... (activity item content) ... -->
                                <div class="activity-content">
                                    <div class="activity-title">{{ alert._source.rule.description }}</div>
                                    <div class="activity-meta">
                                        <!-- ... (other meta items) ... -->
                                        {% if src_ip %}
                                        <span class="meta-item ip-address">
                                            <i class="fi fi-br-network-cloud"></i>
                                            {{ src_ip }}
                                            {% if is_blocked %}
                                                <i class="fi fi-sr-ban blocked-icon" title="This IP is blocked"></i>
                                            {% endif %}
                                        </span>
                                        {% endif %}
                                    </div>
                                </div>
                                <!-- ... (arrow icon) ... -->
                            </div>
                        </a>
                        {% if src_ip and not is_blocked %}
                        <div class="activity-actions">
                            <form action="{{ url_for('ip_blocking.block') }}" method="post" class="block-form">
                                {{ block_form.hidden_tag() }}
                                {{ block_form.ip_address }}
                                {{ block_form.reason }}
                                <button type="submit" class="btn-block" data-ip="{{ src_ip }}" data-reason="{{ alert._source.rule.description }}">
                                    <i class="fi fi-sr-lock"></i> Block IP
                                </button>
                            </form>
                        </div>
                        {% endif %}
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <!-- ... (empty state) ... -->
        {% endif %}
    </div>
{% endblock %}

{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded', function() {
    const blockForms = document.querySelectorAll('.block-form');
    blockForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            const button = event.target.querySelector('.btn-block');
            const ip = button.dataset.ip;
            const reason = button.dataset.reason;
            event.target.querySelector('input[name="ip_address"]').value = ip;
            event.target.querySelector('input[name="reason"]').value = reason;
        });
    });
});
</script>
{% endblock %}
```
**Code Explanation:**
*   `{% set src_ip = ... %}`: We safely extract the source IP from the alert data. Not all alerts have a `srcip`.
*   `{% set is_blocked = src_ip and src_ip in blocked_ips_set %}`: This is the performance-critical check. Because `blocked_ips_set` is a Python set, this lookup is extremely fast, even with thousands of blocked IPs.
*   `{% if is_blocked %}is-blocked{% endif %}`: We conditionally add a CSS class to visually highlight alerts from already-blocked IPs.
*   `{% if src_ip and not is_blocked %}`: We only show the "Block IP" button if there *is* an IP and it's *not* already blocked.
*   **JavaScript**: This script is almost identical to the one on the manage page. It finds the `data-ip` and `data-reason` from the button and populates the hidden form fields before submission.

</details>

<details>
<summary><strong>Step 3.4: Update the Dashboard Route (`app/dashboard/routes.py`)</strong></summary>

Our new dashboard template needs more data than before (`blocked_ips_set` and `block_form`). We must update the route to provide it.

Update `app/dashboard/routes.py`:
```python
# app/dashboard/routes.py

from flask import render_template, Blueprint, flash
from flask_login import login_required

from app.dashboard.services import get_all_wazuh_alerts, get_managers_status

# NEW: Import forms and services for blocking
from app.ip_blocking.forms import BlockIPForm
from app.ip_blocking.services import get_blocked_ips_as_set

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    """
    Renders the main dashboard page.
    """
    manager_statuses = get_managers_status()

    # Check for any failures and flash a message
    failed_managers = [s for s in manager_statuses if not s[1]]
    if failed_managers:
        for manager, is_ok, status, message in failed_managers:
            flash(f"Connection Error for '{manager.name}': {message}", "danger")

    # Fetch alerts
    latest_alerts = get_all_wazuh_alerts(limit_per_manager=25)

    # NEW: Get the set of all blocked IPs for efficient checking in the template
    blocked_ips_set = get_blocked_ips_as_set()

    # NEW: Create a form instance to pass to the template for the block buttons
    block_form = BlockIPForm()

    return render_template(
        "dashboard/index.html",
        alerts=latest_alerts,
        manager_statuses=manager_statuses,
        blocked_ips_set=blocked_ips_set,
        block_form=block_form,
    )
```
**Code Explanation:**
*   We now import `BlockIPForm` and `get_blocked_ips_as_set`.
*   We call `get_blocked_ips_as_set()` to get our fast-lookup set.
*   We create an instance of `BlockIPForm`.
*   We pass both `blocked_ips_set` and `block_form` into the `render_template` function, making them available to our Jinja2 template.

</details>

<details>
<summary><strong>Step 3.5: Add the CSS Styles</strong></summary>

The final step is to add the CSS that makes our new UI elements look good and function correctly. These changes add the sidebar layout, table styles, and the interactive elements on the dashboard.

Because CSS is declarative and less about logic, you can copy and paste these files. The important parts to note are the styles for `.is-blocked` and `.activity-actions` which provide direct visual feedback for the new feature.

*   Create `app/static/css/layout.css` and paste the content from the `after.txt` file.
*   Update `app/static/css/dashboard.css` with the content from the `after.txt` file.
*   Update `app/static/css/style.css` with the content from the `after.txt` file.

</details>

***

### Conclusion

Congratulations! You have successfully completed a major refactor of the LAMIS application.

Let's review what we accomplished:
1.  **🏛️ Structure:** We created a brand new, self-contained `ip_blocking` module, adhering to the Single Responsibility Principle.
2.  **🔐 Security:** We stored credentials in the environment, used WTForms for validation and CSRF protection, and validated all inputs.
3.  **💾 Database:** We added a new `BlockedIP` table using a proper `flask db migrate` and `upgrade` workflow, creating a reliable source of truth.
4.  **⚙️ Logic:** We built a robust service layer that orchestrates database writes and external API calls, including critical rollback logic to maintain data consistency.
5.  **🎨 UI/UX:** We implemented a complete application layout overhaul and integrated the new blocking feature seamlessly into the dashboard, providing clear visual feedback and interactive controls.
6.  **⚡ Performance:** We used an efficient `set` for IP lookups on the dashboard to ensure the UI remains fast, even with a large blocklist.

The foundation we've laid here—Blueprints, the service layer, secure forms, and database migrations—is the blueprint for all future development on LAMIS. The application is now more secure, more maintainable, and a pleasure to work on.

Well done.