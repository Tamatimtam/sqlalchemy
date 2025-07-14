# LAMIS Refactoring Guide: From Monolithic to Modern

Welcome to this comprehensive guide on refactoring our LAMIS application. The previous version served its purpose, but it suffered from performance issues and was difficult to maintain. When a user loaded the dashboard, the server would block while fetching data directly from every Wazuh manager. This was slow and inefficient.

Our goal with this refactor is to create a system that is:

1.  **Performant:** The user interface will feel instant, regardless of how much data we're processing.
2.  **Scalable:** The architecture will support more Wazuh managers and more data without slowing down.
3.  **Maintainable:** The code will be clean, modular, and easy for new developers to understand.
4.  **Resilient:** The system will be more robust, with clear separation between the web interface and background data processing.

To achieve this, we will introduce two major architectural changes:

*   **Redis Caching:** We will use Redis, a high-speed in-memory database, to cache the alert data. This means we only have to ask Wazuh for data once every few minutes, not every time a user loads the page.
*   **Decoupled Scheduler:** We will create a separate Python process (`scheduler.py`) whose only job is to fetch data from Wazuh and put it into the Redis cache. This completely separates the slow data-fetching task from the fast web-serving task.

This guide is broken down into logical parts. Take your time, understand each step, and don't hesitate to take breaks. Let's build a better LAMIS together.

---

## Part 1: Setting Up Our New Infrastructure (Redis)

Before we write any code, we need to set up the new tool in our toolbox: **Redis**.

<details>
<summary><strong>🧠 What is Redis and Why Do We Need It?</strong></summary>

Think of our main PostgreSQL database as a massive, organized library. It's great for storing data permanently and safely, but finding a specific book can take a little time.

**Redis**, on the other hand, is like a librarian's personal desk with a small stack of the most frequently requested books. It's incredibly fast because it keeps everything in memory (RAM) instead of on a disk.

We will use Redis for two key purposes:

1.  **Caching:** Our new `scheduler` process will do the slow work of getting alerts from Wazuh. It will then store the final, processed list of alerts in Redis. When a user opens the LAMIS dashboard, our Flask app will read the data instantly from the Redis cache instead of making slow calls to Wazuh. This is the secret to a fast UI.
2.  **Messaging (Pub/Sub):** Redis has a "Publish/Subscribe" system. This lets different parts of our application communicate without being directly connected. We will use this to allow our main Flask app to send a "refresh now" message to the scheduler, telling it to fetch new data immediately.

By adding Redis, we are making a trade-off: we use a bit more server memory in exchange for a massive gain in application speed and responsiveness.
</details>

### Step 1.1: Update `docker-compose.yaml` to include Redis

We use Docker to manage our services, so adding Redis is as simple as adding a new service definition to our `docker-compose.yaml` file.

**File to Edit:** `/docker-compose.yaml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    container_name: sqlalchemy_postgres
    environment:
      POSTGRES_DB: orm_db # Database name
      POSTGRES_USER: postgres # Database user
      POSTGRES_PASSWORD: password # Database password
    ports:
      - "5432:5432" # Expose PostgreSQL port
    volumes:
      - postgres_data:/var/lib/postgresql/data # Persist data after container is stopped / deleted
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: lamis_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **`redis:`**: This defines a new service named `redis`.
*   **`image: redis:7-alpine`**: We're using the official Redis image, specifically the `alpine` version, which is lightweight and secure.
*   **`container_name: lamis_redis`**: A friendly name for our container.
*   **`ports: - "6379:6379"`**: This maps port `6379` from our local machine to port `6379` inside the container. `6379` is the default port for Redis.
*   **`volumes: - redis_data:/data`**: This creates a persistent volume. It means that even if we stop and restart the Redis container, any data it might have saved to disk won't be lost.
*   **`volumes: redis_data:`**: At the bottom of the file, we declare `redis_data` to make it a named volume managed by Docker.

After saving this file, run `docker-compose up -d` in your terminal. You will see a new `lamis_redis` container being created and started alongside your PostgreSQL container.
</details>

### Step 1.2: Update Project Dependencies

Our Python application needs a "driver" to talk to Redis. We also need a library to run our scheduled jobs.

**File to Edit:** `/req.txt`

```
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

# NEW: High-performance, in-memory cache for storing fetched data
redis

# NEW: The job scheduler for running our background tasks
APScheduler
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **`redis`**: This is the official Python client library for Redis. It gives us the functions we need (like `get`, `set`, `publish`) to interact with the Redis server.
*   **`APScheduler`**: Stands for "Advanced Python Scheduler". This is a powerful and flexible library that allows us to run functions (jobs) at specific intervals (e.g., every 5 minutes) or at specific times. We'll use this to power our `scheduler.py`.

After saving this file, run `pip install -r req.txt` in your virtual environment to install the new packages.
</details>

### Step 1.3: Update Environment and Configuration

We need to tell our Flask app how to connect to our new Redis container. As per our principles, we never hardcode connection details. We use environment variables.

**File to Edit:** `/.env`

```
SECRET_KEY='this-is-a-secret-please-change-it'
DATABASE_URL='postgresql://postgres:password@localhost:5432/orm_db'
ENCRYPTION_KEY='???='

# --- NEW: Redis Configuration ---
REDIS_URL='redis://localhost:6379/0'

# --- OPNsense Firewall Integration ---
# The base URL of your OPNsense firewall
OPNSENSE_URL='https:///???:8443'

# The API Key generated in OPNsense (System -> Access -> Users -> API Keys)
OPNSENSE_API_KEY='???+Id'

# The API Secret corresponding to the key
OPNSENSE_API_SECRET='???'

# The EXACT name of the IP Alias you created in OPNsense to hold the blocked IPs
OPNSENSE_ALIAS_NAME='???'
```

**File to Edit:** `/config.py`

```python
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

    # NEW: Redis Cache
    REDIS_URL = os.environ.get("REDIS_URL")

    # OPNsense Firewall Integration
    OPNSENSE_URL = os.environ.get("OPNSENSE_URL")
    OPNSENSE_API_KEY = os.environ.get("OPNSENSE_API_KEY")
    OPNSENSE_API_SECRET = os.environ.get("OPNSENSE_API_SECRET")
    OPNSENSE_ALIAS_NAME = os.environ.get("OPNSENSE_ALIAS_NAME")
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   In `.env`, we add `REDIS_URL='redis://localhost:6379/0'`. This is a standard connection string. `localhost:6379` is the address of the Redis container we just launched. The `/0` at the end specifies which Redis database to use (Redis supports multiple logical databases, and 0 is the default).
*   In `config.py`, we simply load this new environment variable into our `Config` object. This makes it available throughout our Flask application via `current_app.config['REDIS_URL']`.
</details>

**Checkpoint:** We have now successfully provisioned our Redis infrastructure, updated our dependencies, and configured our application to be aware of it. We are ready to build the new decoupled components.

---

## Part 2: Building the Decoupled Scheduler

This is the most significant architectural change. We are creating a new, standalone Python script that will run *in the background*, completely separate from the Flask web server.

### Step 2.1: Create the Task Service Module

First, we'll create a new module to hold the actual logic for our background job. This adheres to the **Single Responsibility Principle**. This file's only job is to fetch and process data from Wazuh.

**File to Create:** `/app/tasks/services.py`

```python
# app/tasks/services.py
"""
Service functions for background tasks.
These functions are designed to be called by the scheduler, not directly by web routes.
They handle the heavy lifting of fetching data from external sources.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
from app.models.wazuh import WazuhManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

# Define constants for our Redis keys to avoid magic strings.
# This makes the code more maintainable.
CONTROL_CHANNEL = "lamis:control"
REDIS_ALERTS_KEY = "lamis:alerts:cached_data"
REDIS_LAST_UPDATE_KEY = "lamis:alerts:last_update_utc"
REDIS_TOTAL_COUNT_KEY = "lamis:alerts:total_count_24h"


def fetch_and_cache_all_wazuh_alerts(app) -> None:
    """
    The main job executed by the scheduler.
    It fetches alerts from all active Wazuh managers for the last 24 hours,
    aggregates them, and stores them in the Redis cache.
    """
    # We must operate within the application context to access the database and config.
    with app.app_context():
        logger = app.logger
        logger.info("Background task started: Fetching Wazuh alerts.")

        active_managers = WazuhManager.query.filter_by(is_active=True).all()
        if not active_managers:
            logger.warning("No active Wazuh managers configured. Skipping fetch.")
            return

        encryption_key = app.config["ENCRYPTION_KEY"]
        redis_client = app.redis

        all_alerts = []
        # Use a thread pool to fetch from all managers concurrently.
        with ThreadPoolExecutor(max_workers=len(active_managers) or 1) as executor:
            future_to_manager = {
                executor.submit(
                    _fetch_alerts_from_single_manager,
                    manager,
                    encryption_key,
                    logger,
                ): manager
                for manager in active_managers
            }

            for future in as_completed(future_to_manager):
                manager = future_to_manager[future]
                try:
                    alerts_from_manager = future.result()
                    all_alerts.extend(alerts_from_manager)
                except Exception as exc:
                    logger.error(
                        f"Manager {manager.name} generated an exception: {exc}"
                    )

        # Sort all alerts from all sources by timestamp descending.
        logger.info(f"Total alerts fetched from all managers: {len(all_alerts)}")
        all_alerts.sort(key=lambda x: x["_source"]["timestamp"], reverse=True)

        # Store the results in Redis.
        try:
            # We serialize the list of alerts into a JSON string.
            # Redis stores strings, so this is a standard and efficient way to cache complex objects.
            serialized_alerts = json.dumps(all_alerts)

            # Use a pipeline for atomic operations.
            # This ensures that all commands are sent to Redis at once.
            pipe = redis_client.pipeline()
            pipe.set(REDIS_ALERTS_KEY, serialized_alerts)
            pipe.set(REDIS_LAST_UPDATE_KEY, datetime.now(timezone.utc).isoformat())
            pipe.set(REDIS_TOTAL_COUNT_KEY, len(all_alerts))
            pipe.execute()

            logger.info(f"Successfully cached {len(all_alerts)} alerts in Redis.")

        except Exception as e:
            logger.error(f"Failed to cache alerts in Redis: {e}")

        logger.info("Background task finished.")


def trigger_data_refresh(app) -> bool:
    """
    Publishes a command to the Redis control channel to trigger an immediate data fetch.
    Returns:
        True if the command was published, False otherwise.
    """
    try:
        app.redis.publish(CONTROL_CHANNEL, "REFRESH_DATA")
        app.logger.info("Published 'REFRESH_DATA' command to control channel.")
        return True
    except Exception as e:
        app.logger.error(f"Failed to publish refresh command to Redis: {e}")
        return False


def _fetch_alerts_from_single_manager(
    manager: WazuhManager, encryption_key: str, logger: logging.Logger
) -> List[Dict[str, Any]]:
    """
    Fetches alerts from a single Wazuh manager.
    MODIFIED: Now includes a time range query for the last 24 hours.
    """
    # 1. Define the search endpoint.
    wazuh_url: str = f"{manager.url}/wazuh-alerts-*/_search"

    # 2. ⚡️ PERFORMANCE: This is the crucial change.
    # We now filter by timestamp, asking Wazuh only for alerts in the last 24 hours.
    # We also increase the 'size' limit to get a good batch of recent data.
    # Calculate timestamp for 24 hours ago

    twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    timestamp_filter = twenty_four_hours_ago.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    query: Dict[str, Any] = {
        "size": 10000,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "timestamp": {
                    "gte": timestamp_filter,
                    "format": "strict_date_optional_time",
                }
            }
        },
    }

    # 3. Get credentials securely.
    password = manager.get_decrypted_password(encryption_key)
    if not password:
        logger.error(f"Could not decrypt password for {manager.name}, skipping.")
        return []

    logger.debug(f"Fetching alerts from manager: {manager.name} for the last 24h.")
    try:
        with requests.Session() as session:
            session.auth = (manager.username, password)
            response: requests.Response = session.post(
                wazuh_url,
                json=query,
                verify=False,
                timeout=30,  # Increased timeout for larger queries
            )
            response.raise_for_status()

            data: Dict[str, Any] = response.json()
            alerts = data.get("hits", {}).get("hits", [])

            # Add context to each alert for the UI.
            for alert in alerts:
                alert["_source_manager_name"] = manager.name
                alert["_source_manager_id"] = manager.id

            logger.info(f"Fetched {len(alerts)} alerts from {manager.name}.")
            return alerts

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch alerts from {manager.name} ({manager.url}): {e}")
        return []
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **Constants:** We define constants for our Redis keys (`REDIS_ALERTS_KEY`, etc.). This is a best practice that prevents typos and makes the code easier to read and maintain.
*   **`fetch_and_cache_all_wazuh_alerts`**: This is the main function our scheduler will call.
    *   It takes the `app` object as an argument so it can work within the Flask application context to access the database (`WazuhManager.query`), config (`app.config`), and logger (`app.logger`).
    *   It fetches all alerts concurrently using a `ThreadPoolExecutor`, just like before.
    *   **The Big Change:** After fetching and sorting the alerts, it connects to Redis. It uses `json.dumps()` to serialize the Python list of dictionaries into a single JSON string. It then stores this string in Redis using `pipe.set(REDIS_ALERTS_KEY, serialized_alerts)`.
    *   It also stores the current timestamp and total alert count in separate keys for metadata.
    *   Using `pipe = redis_client.pipeline()` is a performance optimization. It bundles all the `set` commands into a single network request to Redis, which is more efficient.
*   **`_fetch_alerts_from_single_manager`**: We've made a critical performance improvement here.
    *   The Elasticsearch query now includes a `range` filter on the `timestamp` field: `"gte": timestamp_filter` (`gte` means "greater than or equal to").
    *   This tells Wazuh/Elasticsearch to only return records from the last 24 hours. This is vastly more efficient than fetching all alerts and filtering in Python.
*   **`trigger_data_refresh`**: This simple function connects to Redis and `publish`es a message to the `CONTROL_CHANNEL`. Any process listening to this channel (our scheduler) will receive this message. This is the "Pub" part of Pub/Sub.
</details>

### Step 2.2: Create the Scheduler Script

Now we create the script that will run our task on a schedule. This script is the "daemon" or "service" that will live in the background.

**File to Create:** `/scheduler.py`

```python
# scheduler.py
"""
LAMIS Background Scheduler

This script runs as a separate process from the main Flask web server.
Its purpose is to periodically run background jobs, such as fetching data
from external APIs and caching it.

This decoupling is essential for application performance and scalability.

To run this: `python scheduler.py`
"""

import logging
import time
import threading
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from app import create_app
from app.tasks.services import fetch_and_cache_all_wazuh_alerts

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define a constant for our Redis Pub/Sub channel
CONTROL_CHANNEL = "lamis:control"


def listen_for_commands(app, scheduler):
    """
    Runs in a separate thread to listen for commands on a Redis channel.
    This allows the main web app to trigger jobs in the scheduler process.
    """
    with app.app_context():
        pubsub = app.redis.pubsub()
        pubsub.subscribe(CONTROL_CHANNEL)
        logging.info(f"Scheduler listening for commands on channel '{CONTROL_CHANNEL}'")
        for message in pubsub.listen():
            if message["type"] == "message":
                command = message["data"].decode("utf-8")
                logging.info(f"Received command: {command}")
                if command == "REFRESH_DATA":
                    # Modify the job to run now, instead of waiting for the next interval.
                    scheduler.get_job("fetch_wazuh_alerts_job").modify(
                        next_run_time=datetime.now()
                    )


def run_scheduler():
    """Initializes and runs the scheduler and command listener."""
    app = create_app()
    app.app_context().push()

    scheduler = BackgroundScheduler(daemon=True)

    scheduler.add_job(
        fetch_and_cache_all_wazuh_alerts,
        "interval",
        seconds=10,
        args=[app],
        id="fetch_wazuh_alerts_job",
        next_run_time=datetime.now(),
    )

    # Start the command listener in a separate thread
    listener_thread = threading.Thread(
        target=listen_for_commands, args=(app, scheduler), daemon=True
    )
    listener_thread.start()

    scheduler.start()
    logging.info("Scheduler started. Press Ctrl+C to exit.")

    try:
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logging.info("Scheduler shut down gracefully.")


if __name__ == "__main__":
    run_scheduler()
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **`run_scheduler()`**: This is the main function of the script.
    *   `app = create_app()`: It creates an instance of our Flask application. This is crucial because it gives the scheduler access to our database models, configuration, and the Redis connection we'll set up soon.
    *   `scheduler = BackgroundScheduler()`: This creates a scheduler instance that runs in a background thread.
    *   `scheduler.add_job(...)`: This is where we schedule our task.
        *   `fetch_and_cache_all_wazuh_alerts`: The function to run.
        *   `"interval", seconds=300`: Tells the scheduler to run this function every 300 seconds (5 minutes). I've set it to `10` seconds in the final code for easier testing, but `300` is a more realistic production value.
        *   `args=[app]`: Passes the `app` object to our function.
        *   `id="fetch_wazuh_alerts_job"`: Gives the job a unique name so we can refer to it later.
        *   `next_run_time=datetime.now()`: Tells the scheduler to run the job immediately on startup, instead of waiting for the first interval to pass.
*   **`listen_for_commands()`**: This function is the "Sub" part of our Pub/Sub system.
    *   It runs in a separate `threading.Thread`, so it doesn't block the main scheduler.
    *   `pubsub = app.redis.pubsub()`: Creates a Redis Pub/Sub object.
    *   `pubsub.subscribe(CONTROL_CHANNEL)`: Subscribes to our control channel.
    *   `for message in pubsub.listen()`: This is a blocking loop. It waits indefinitely for messages to arrive on the channel.
    *   When a "REFRESH\_DATA" message arrives, it finds the job by its ID and uses `.modify(next_run_time=datetime.now())` to tell the scheduler "run this job right now!".
*   **`if __name__ == "__main__":`**: This standard Python construct ensures that `run_scheduler()` is called only when the script is executed directly (`python scheduler.py`).

To run this, you will open a **second terminal window** (separate from your Flask `run.py` terminal) and run `python scheduler.py`. You should see log messages indicating that it has started.
</details>

---

## Part 3: Backend Refactoring for Caching

Now that our scheduler is busy putting data *into* Redis, we need to change our Flask application to read data *from* Redis.

### Step 3.1: Initialize Redis in the App Factory

We need to establish the Redis connection when the Flask app starts. The application factory (`create_app`) is the perfect place for this.

**File to Edit:** `/app/__init__.py`

```python
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from config import Config
from flask_sqlalchemy import SQLAlchemy
from app.models import db
from app.models.user import User
from app.models.state import InitializationState
from app.models.wazuh import WazuhManager

# NEW: Import the new BlockedIP model so Flask-Migrate can see it
from app.models.ip_block import BlockedIP
import logging
import redis

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

    # NEW: Initialize Redis connection and attach it to the app object
    # This makes it easily accessible as `current_app.redis` in our routes.
    try:
        app.redis = redis.from_url(app.config["REDIS_URL"])
        # Ping the server to check the connection at startup.
        app.redis.ping()
        app.logger.info("Successfully connected to Redis.")
    except redis.exceptions.ConnectionError as e:
        app.logger.error(f"Could not connect to Redis: {e}")
        # In a real app, you might want to exit or have a fallback.
        # For now, we'll log the error and continue.
        app.redis = None

    with app.app_context():
        from .auth import routes as auth_routes
        from .dashboard import routes as dashboard_routes
        from .alerts import routes as alert_routes
        from .managers import routes as manager_routes

        # NEW: Import and register the ip_blocking blueprint
        from .ip_blocking import routes as ip_blocking_routes
        from .api import routes as api_routes  # NEW: Import API routes

        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(dashboard_routes.bp)
        app.register_blueprint(alert_routes.bp)
        app.register_blueprint(manager_routes.bp)
        app.register_blueprint(ip_blocking_routes.bp)
        app.register_blueprint(api_routes.bp)  # NEW: Register API blueprint

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
            # Allow requests to static files, API, and the setup endpoints
            if request.endpoint and (
                request.endpoint.startswith("static")
                or request.endpoint.startswith("api.")  # NEW: Allow API calls
                or request.endpoint
                in ["auth.setup", "managers.setup_wazuh", "auth.login"]
            ):
                return

            state = InitializationState.query.first()
            if not state or not state.setup_completed:
                # If user is not on setup page and setup is not complete, redirect them
                if request.endpoint != "auth.setup":
                    return redirect(url_for("auth.setup"))
                return

            # If setup is complete, but user is not logged in, let login_manager handle it
            if not current_user.is_authenticated:
                return  # login_manager will redirect to login page

            # Check if any Wazuh managers are configured.
            if WazuhManager.query.count() == 0:
                # If we are here, it means admin is created but no managers exist.
                # Send them to the Wazuh setup page, unless they are already going there.
                if request.endpoint != "managers.setup_wazuh":
                    return redirect(url_for("managers.setup_wazuh"))

        @app.cli.command("init-state")
        def init_state_command():
            if InitializationState.query.first():
                print("State is already initialized.")
                return

            initial_state = InitializationState(setup_completed=False)
            db.session.add(initial_state)
            db.session.commit()
            print("Database initialization state created successfully.")

    app.logger.info("LAMIS Application Created")

    return app
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **`import redis`**: We import the new library.
*   **`app.redis = redis.from_url(...)`**: We create the connection using the `REDIS_URL` from our config and attach the connection object directly to the `app` instance. This is a common and convenient pattern.
*   **`app.redis.ping()`**: This command checks the connection to the Redis server. If it fails, it will raise a `ConnectionError`, which we catch to log a helpful error message.
*   **API Blueprint:** We import and register a new blueprint for our internal API, `api_routes.bp`.
*   **`@app.before_request`**: We add `request.endpoint.startswith('api.')` to the list of exceptions. This is crucial! It ensures that our frontend JavaScript can call the API endpoints even if the user is not fully logged in or set up, preventing redirect loops.
</details>

### Step 3.2: Create the Internal API Endpoint

Our frontend will no longer get data directly from the Jinja2 template. Instead, it will make an asynchronous call to an internal API endpoint to fetch the alert data as JSON.

**File to Create:** `/app/api/routes.py`

```python
# app/api/routes.py
"""
Internal API endpoints for the LAMIS frontend.
These routes return JSON data and are consumed by our JavaScript.
"""

import json
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required
from app.tasks.services import (
    REDIS_ALERTS_KEY,
    REDIS_LAST_UPDATE_KEY,
    REDIS_TOTAL_COUNT_KEY,
    trigger_data_refresh,
)

# All routes in this blueprint will be prefixed with /api
bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/alerts")
@login_required
def get_alerts():
    """
    Provides paginated alert data from the Redis cache.
    This is the primary data source for the dynamic dashboard.

    Query Parameters:
        page (int): The page number to retrieve (default: 1).
        per_page (int): The number of items per page (default: 50).
    """
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 25, type=int)

        redis_client = current_app.redis

        # Fetch the cached data from Redis.
        cached_data = redis_client.get(REDIS_ALERTS_KEY)
        last_update = redis_client.get(REDIS_LAST_UPDATE_KEY)
        total_count_24h = redis_client.get(REDIS_TOTAL_COUNT_KEY)

        if not cached_data:
            # This happens if the scheduler hasn't run yet or Redis is empty.
            return jsonify(
                {
                    "alerts": [],
                    "total_alerts": 0,
                    "total_pages": 0,
                    "current_page": page,
                    "last_update": None,
                }
            )

        # The data is stored as a JSON string, so we need to parse it back into a Python list.
        all_alerts = json.loads(cached_data)
        total_alerts = len(all_alerts)

        # ⚡️ PERFORMANCE: We perform pagination here, in the backend.
        # This ensures we only send a small chunk of data to the browser.
        start = (page - 1) * per_page
        end = start + per_page
        paginated_alerts = all_alerts[start:end]

        return jsonify(
            {
                "alerts": paginated_alerts,
                "total_alerts_in_cache": total_alerts,
                "total_alerts_last_24h": int(total_count_24h) if total_count_24h else 0,
                "total_pages": (total_alerts + per_page - 1) // per_page,
                "current_page": page,
                "last_update": last_update.decode("utf-8") if last_update else None,
            }
        )

    except Exception as e:
        current_app.logger.error(f"Error in /api/alerts endpoint: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred."}), 500


@bp.route("/system/refresh", methods=["POST"])
@login_required
def force_refresh():
    """
    Triggers a manual refresh of the Wazuh alert data from the cache.
    """
    success = trigger_data_refresh(current_app)
    if success:
        return jsonify({"message": "Refresh command sent successfully."}), 202
    else:
        return jsonify({"error": "Failed to send refresh command."}), 500
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   **`bp = Blueprint("api", ..., url_prefix="/api")`**: We create a new blueprint. All routes here will start with `/api`.
*   **`@bp.route("/alerts")`**: This is the main endpoint our dashboard will use.
    *   It's incredibly simple: it just connects to Redis (`current_app.redis`), `get`s the cached data, and returns it as JSON.
    *   **Pagination:** Notice how it accepts `page` and `per_page` query parameters. It performs the list slicing (`all_alerts[start:end]`) on the server. This is a huge performance win. Instead of sending potentially thousands of alerts to the browser, we only send a small, manageable chunk (e.g., 25). The browser only has to render what's visible.
    *   **Deserialization:** `json.loads(cached_data)` is the reverse of `json.dumps()`. It converts the JSON string from Redis back into a Python list.
    *   **Metadata:** The JSON response includes helpful metadata like `total_pages` and `current_page`, which our frontend will use to build the pagination controls.
*   **`@bp.route("/system/refresh", methods=["POST"])`**: This endpoint provides a way for the UI to trigger our Pub/Sub mechanism. When the user clicks our new "Refresh Now" button, the frontend will call this endpoint, which in turn calls our `trigger_data_refresh` service function.
</details>

### Step 3.3: Simplify the Dashboard Route and Services

The dashboard route no longer needs to fetch alerts. Its only job is to render the main HTML "shell" of the page. The JavaScript will handle filling it with data.

**File to Delete:** `/app/dashboard/services.py`
This file is no longer needed. The `get_all_wazuh_alerts` function has been replaced by `fetch_and_cache_all_wazuh_alerts` in `app/tasks/services.py`. The `get_managers_status` function is more related to managers, so we will move it.

**File to Edit:** `/app/managers/services.py` (We are moving a function here)

```python
from typing import Tuple, Literal, List
import requests
from flask import current_app
from concurrent.futures import ThreadPoolExecutor, as_completed

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
            response = session.get(test_url, verify=False, timeout=3)

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


# NEW: Moved this function here from dashboard/services.py
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

**File to Edit:** `/app/dashboard/routes.py`

```python
from flask import render_template, Blueprint, flash
from flask_login import login_required

# REMOVED: No longer need to fetch alerts here.
# from app.dashboard.services import get_all_wazuh_alerts
from app.managers.services import get_managers_status

# NEW: Import forms and services for blocking
from app.ip_blocking.forms import BlockIPForm
from app.ip_blocking.services import get_blocked_ips_as_set

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    """
    Renders the main dashboard page shell.
    The actual alert data will be loaded asynchronously via JavaScript.
    """
    manager_statuses = get_managers_status()

    # Check for any failures and flash a message. This is still useful.
    failed_managers = [s for s in manager_statuses if not s[1]]
    if failed_managers:
        for manager, is_ok, status, message in failed_managers:
            flash(f"Connection Error for '{manager.name}': {message}", "danger")

    # We still need these for the stats boxes and block buttons.
    blocked_ips_set = get_blocked_ips_as_set()
    block_form = BlockIPForm()

    # We no longer pass 'alerts' to the template. The frontend will fetch it.
    return render_template(
        "dashboard/index.html",
        manager_statuses=manager_statuses,
        blocked_ips_set=list(blocked_ips_set),
        block_form=block_form,
    )
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   The `get_all_wazuh_alerts` import and call are completely removed from `routes.py`.
*   The `alerts` variable is no longer passed to `render_template`.
*   The `get_managers_status` function was moved to `app/managers/services.py` because it is more closely related to manager functionality. This improves cohesion and follows the Single Responsibility Principle.
*   We now pass `blocked_ips_set` as a list. This will be embedded as JSON in the HTML for our JavaScript to use.
</details>

---

## Part 4: The Frontend Overhaul with Modern JavaScript

This is where the user will see the biggest difference. We are transforming the dashboard from a static, server-rendered page into a dynamic, app-like experience.

### Step 4.1: Create the Modular JavaScript Files

We will follow the **Single Responsibility Principle** for our frontend code. Each file will have a clear, defined purpose. This makes the code incredibly easy to navigate and debug.

**Create the following directory and files:**

*   `/app/static/js/dashboard/`
    *   `main.js` (The entry point of our application)
    *   `state.js` (Manages the shared state and DOM elements)
    *   `api.js` (Handles all communication with our backend API)
    *   `ui.js` (Handles all DOM manipulation and rendering)
    *   `events.js` (Handles all user interactions and event listeners)

**File to Create:** `/app/static/js/dashboard/main.js`

```javascript
// app/static/js/dashboard/main.js

import { fetchAndRenderAlerts, checkForNewData } from './api.js';
import { initializeEventListeners } from './events.js';
import { showLoadingState, updateNotificationBanner } from './ui.js';

/**
 * Initializes the dashboard application.
 * This function is the main entry point.
 */
function initializeDashboard() {
    showLoadingState();
    fetchAndRenderAlerts();
    initializeEventListeners();
    checkForNewData();
    updateNotificationBanner();
}

// Wait for the DOM to be fully loaded before initializing the dashboard.
document.addEventListener('DOMContentLoaded', initializeDashboard);
```

**File to Create:** `/app/static/js/dashboard/state.js`

```javascript
// app/static/js/dashboard/state.js

/**
 * A simple object to hold the shared state of our dashboard.
 */
export const state = {
    currentPage: 1,
    totalPages: 1,
    isLoading: false,
    lastUpdate: null,
    hasNewData: false,
};

/**
 * Caching DOM elements for performance.
 */
export const elements = {
    activityListContainer: document.getElementById('activity-list-container'),
    paginationContainer: document.getElementById('pagination-container'),
    loadingSpinner: document.getElementById('loading-spinner'),
    emptyState: document.getElementById('empty-state'),
    alertCountSpan: document.getElementById('alert-count-span'),
    recentAlertsValue: document.getElementById('recent-alerts-value'),
    newDataNotification: document.getElementById('new-data-notification'),
    // We convert the JSON data from the script tag into a Set for efficient lookups.
    blockedIpsSet: new Set(JSON.parse(document.getElementById('blocked-ips-data').textContent || '[]'))
};
```

**File to Create:** `/app/static/js/dashboard/api.js`

```javascript
// app/static/js/dashboard/api.js

import { state } from './state.js';
import { renderAlerts, showErrorState, hideLoadingState } from './ui.js';

/**
 * Fetches alert data from our internal API and triggers rendering.
 * @param {number} page - The page number to fetch.
 */
export async function fetchAndRenderAlerts(page = 1) {
    if (state.isLoading) return; // Prevent multiple simultaneous requests
    
    state.isLoading = true;
    
    try {
        const response = await fetch(`/api/alerts?page=${page}&per_page=25`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        renderAlerts(data);
        
        // After a successful fetch, if there was a new data notification,
        // we can assume the user has now seen the latest data.
        state.hasNewData = false;

    } catch (error) {
        console.error("Failed to fetch alerts:", error);
        showErrorState("Could not load alert data. Please try again later.");
    } finally {
        state.isLoading = false;
        hideLoadingState();
    }
}

/**
 * Periodically checks if new data is available on the server.
 */
export function checkForNewData() {
    setInterval(async () => {
        // Don't check if a fetch is already in progress or if we already know about new data.
        if (state.isLoading || state.hasNewData) return;

        try {
            const response = await fetch('/api/alerts?page=1&per_page=1');
            if (!response.ok) return;

            const data = await response.json();
            
            // If the last update time from the server is different from our client-side state,
            // it means the background worker has cached new data.
            if (state.lastUpdate && data.last_update && state.lastUpdate !== data.last_update) {
                state.hasNewData = true;
            }
        } catch (error) {
            console.error("Failed to check for new data:", error);
        }
    }, 15000); // Check every 15 seconds
}
```

**File to Create:** `/app/static/js/dashboard/ui.js`

```javascript
// app/static/js/dashboard/ui.js

import { state, elements } from './state.js';
import { handlePageInputChange, handlePaginationClick } from './events.js';

/**
 * A simple utility to escape HTML to prevent XSS attacks.
 * @param {string} str - The string to escape.
 * @returns {string} The escaped string.
 */
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    const p = document.createElement("p");
    p.textContent = str;
    return p.innerHTML;
}

/**
 * Creates the HTML for the "Block IP" button form.
 * @param {string} ip - The IP address to block.
 * @param {string} reason - The reason for blocking.
 * @returns {string} The HTML string for the form.
 */
function createBlockButtonHTML(ip, reason) {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    return `
        <div class="activity-actions">
            <form action="/blocking/block" method="post" class="block-form">
                <input type="hidden" name="csrf_token" value="${csrfToken}">
                <input type="hidden" name="ip_address" value="${escapeHTML(ip)}">
                <input type="hidden" name="reason" value="${escapeHTML(reason)}">
                <button type="submit" class="btn-block">
                    <i class="fi fi-sr-lock"></i> Block IP
                </button>
            </form>
        </div>
    `;
}

/**
 * Creates the HTML string for a single alert item.
 * @param {object} alert - The alert object from the API.
 * @returns {string} The HTML string for the alert item.
 */
function createAlertHTML(alert) {
    const src_ip = alert._source.data?.srcip;
    const is_blocked = src_ip && elements.blockedIpsSet.has(src_ip);
    const level = alert._source.rule.level;
    
    let iconClass = 'low';
    let iconName = 'fi-sr-eye';
    if (level >= 10) { iconClass = 'critical'; iconName = 'fi-sr-shield-exclamation'; }
    else if (level >= 7) { iconClass = 'high'; iconName = 'fi-sr-triangle-warning'; }
    else if (level >= 4) { iconClass = 'medium'; iconName = 'fi-sr-info'; }

    return `
        <div class="activity-item-wrapper">
            <a href="/alert/${alert._source_manager_id}/${alert._index}/${alert._id}" class="activity-link">
                <div class="activity-item ${is_blocked ? 'is-blocked' : ''}">
                    <div class="activity-icon">
                        <i class="fi ${iconName} ${iconClass}"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${escapeHTML(alert._source.rule.description)}</div>
                        <div class="activity-meta">
                            <span class="meta-item"><i class="fi fi-br-database"></i> ${escapeHTML(alert._source_manager_name)}</span>
                            <span class="meta-item"><i class="fi fi-br-computer"></i> ${escapeHTML(alert._source.agent.name)}</span>
                            <span class="meta-item"><i class="fi fi-br-clock"></i> ${new Date(alert._source.timestamp).toLocaleString()}</span>
                            <span class="meta-item level-${level}"><i class="fi fi-br-signal-alt-3"></i> Level ${level}</span>
                            ${src_ip ? `
                            <span class="meta-item ip-address">
                                <i class="fi fi-br-network-cloud"></i> ${escapeHTML(src_ip)}
                                ${is_blocked ? '<i class="fi fi-sr-ban blocked-icon" title="This IP is blocked"></i>' : ''}
                            </span>` : ''}
                        </div>
                    </div>
                    <div class="activity-arrow"><i class="fi fi-br-angle-right"></i></div>
                </div>
            </a>
            ${(src_ip && !is_blocked) ? createBlockButtonHTML(src_ip, alert._source.rule.description) : ''}
        </div>
    `;
}

/**
 * Renders the pagination controls with the new input field.
 */
function renderPagination() {
    if (state.totalPages <= 1) {
        elements.paginationContainer.innerHTML = '';
        return;
    }

    elements.paginationContainer.innerHTML = `
        <button class="btn-page" data-page="${state.currentPage - 1}" ${state.currentPage === 1 ? 'disabled' : ''}>
            « Previous
        </button>
        <span class="page-info">
            Page 
            <input type="number" class="page-input" value="${state.currentPage}" min="1" max="${state.totalPages}">
            of ${state.totalPages}
        </span>
        <button class="btn-page" data-page="${state.currentPage + 1}" ${state.totalPages === state.currentPage ? 'disabled' : ''}>
            Next »
        </button>
    `;
}

/**
 * Updates the statistic cards at the top of the dashboard.
 * @param {object} data - The data object from the API response.
 */
function updateStatCards(data) {
    if (elements.alertCountSpan) {
        elements.alertCountSpan.textContent = `${data.total_alerts_last_24h} alerts in last 24h`;
    }
    if (elements.recentAlertsValue) {
        elements.recentAlertsValue.textContent = data.total_alerts_last_24h;
    }
}

/**
 * Main render function to update the UI based on API data.
 * @param {object} data - The data object from the API.
 */
export function renderAlerts(data) {
    // Update state with data from the API
    state.currentPage = data.current_page;
    state.totalPages = data.total_pages;
    state.lastUpdate = data.last_update;

    updateStatCards(data);

    if (data.alerts && data.alerts.length > 0) {
        elements.activityListContainer.innerHTML = data.alerts.map(alert => createAlertHTML(alert)).join('');
        elements.emptyState.classList.add('hidden');
        elements.activityListContainer.classList.remove('hidden');
    } else {
        showEmptyState();
    }

    renderPagination();
}

// --- UI STATE HELPERS ---

export function showLoadingState() {
    elements.loadingSpinner.classList.remove('hidden');
    elements.activityListContainer.classList.add('hidden');
    elements.emptyState.classList.add('hidden');
}

export function hideLoadingState() {
    elements.loadingSpinner.classList.add('hidden');
}

export function showEmptyState() {
    elements.emptyState.classList.remove('hidden');
    elements.activityListContainer.classList.add('hidden');
}

export function showErrorState(message) {
    elements.emptyState.classList.remove('hidden');
    elements.emptyState.innerHTML = `
        <i class="fi fi-br-triangle-warning" style="color: var(--danger-color);"></i>
        <p>Error</p>
        <small>${message}</small>
    `;
}

/**
 * Checks the state and shows or hides the "New Data Available" notification.
 */
export function updateNotificationBanner() {
    setInterval(() => {
        if (state.hasNewData) {
            elements.newDataNotification.classList.remove('hidden');
        } else {
            elements.newDataNotification.classList.add('hidden');
        }
    }, 1000); // Check every second
}
```

**File to Create:** `/app/static/js/dashboard/events.js`

```javascript
// app/static/js/dashboard/events.js

import { state, elements } from './state.js';
import { fetchAndRenderAlerts } from './api.js';
import { showLoadingState } from './ui.js';

/**
 * Handles clicks on the pagination buttons (Next/Previous).
 * @param {Event} e - The click event.
 */
export function handlePaginationClick(e) {
    const button = e.target.closest('.btn-page');
    if (button) {
        const page = parseInt(button.dataset.page);
        if (page > 0 && page <= state.totalPages) {
            showLoadingState();
            fetchAndRenderAlerts(page);
        }
    }
}

/**
 * Handles the form submission for the page number input.
 * @param {Event} e - The submit event.
 */
export function handlePageInputChange(e) {
    if (e.key === 'Enter') {
        const input = e.target;
        let page = parseInt(input.value, 10);

        // Validate the entered page number
        if (isNaN(page) || page < 1) {
            page = 1;
        } else if (page > state.totalPages) {
            page = state.totalPages;
        }

        showLoadingState();
        fetchAndRenderAlerts(page);
        
        // Prevent form submission if it's part of a form
        e.preventDefault();
    }
}

/**
 * Adds all necessary event listeners to the dashboard elements.
 * Uses event delegation on containers for efficiency.
 */
async function handleRefreshClick() {
    const button = document.getElementById('refresh-now-button');
    button.disabled = true;
    button.innerHTML = '<i class="fi fi-br-spinner" style="animation: spin 1s linear infinite;"></i> Refreshing...';

    try {
        await fetch('/api/system/refresh', { method: 'POST' });
        // Wait a moment for the scheduler to process and cache the data
        await new Promise(resolve => setTimeout(resolve, 2000)); 
        showLoadingState();
        fetchAndRenderAlerts(1);
    } catch (error) {
        console.error('Failed to trigger refresh:', error);
    } finally {
        button.disabled = false;
        button.innerHTML = '<i class="fi fi-br-refresh"></i> Refresh Now';
    }
}

export function initializeEventListeners() {
    // Listener for pagination controls (buttons and input)
    elements.paginationContainer.addEventListener('click', handlePaginationClick);
    elements.paginationContainer.addEventListener('keydown', handlePageInputChange);

    // Listener for the "Refresh Now" button
    const refreshButton = document.getElementById('refresh-now-button');
    if (refreshButton) {
        refreshButton.addEventListener('click', handleRefreshClick);
    }

    // Listener for the "New Data" notification banner
    if (elements.newDataNotification) {
        elements.newDataNotification.addEventListener('click', () => {
            showLoadingState();
            fetchAndRenderAlerts(1); // Go back to page 1 to show the newest data
            state.hasNewData = false; // Reset the flag
        });
    }

    // Listener for dynamically created "Block IP" forms
    elements.activityListContainer.addEventListener('submit', function(event) {
        if (event.target.matches('.block-form')) {
            // The form is already populated with the correct data,
            // so we just let it submit normally.
            // A confirmation could be added here.
        }
    });
}
```

<details>
<summary><strong>JavaScript Concepts Explained</strong></summary>

*   **Modules (`import`/`export`)**: We use `export` in files like `state.js` to make variables (`state`, `elements`) and functions available to other files. We use `import` in files like `main.js` to use them. This is the modern, standard way to organize JavaScript and avoid polluting the global namespace.
*   **`async/await`**: The `fetchAndRenderAlerts` function in `api.js` is marked `async`. This allows us to use the `await` keyword. `await fetch(...)` pauses the function until the network request is complete, making asynchronous code look clean and synchronous. It's a huge improvement over older callback-based methods.
*   **`fetch` API**: This is the modern browser API for making network requests (like to our `/api/alerts` endpoint). It's promise-based, which works perfectly with `async/await`.
*   **State Management (`state.js`)**: We have a single, simple `state` object. All parts of our application read from and write to this single source of truth. This prevents confusion and bugs that arise when state is scattered all over the code.
*   **DOM Manipulation (`ui.js`)**: This file is the only one that directly changes the HTML. It receives data and renders it. Notice the `escapeHTML` function. **This is a critical security step.** We are dynamically creating HTML from API data. We must *always* escape this data to prevent Cross-Site Scripting (XSS) attacks.
*   **Event Delegation (`events.js`)**: Instead of adding a click listener to every single pagination button, we add *one* listener to the `paginationContainer`. The `handlePaginationClick` function then checks if the clicked element `e.target` was a button. This is far more efficient, especially for dynamically created elements.
</details>

### Step 4.2: Overhaul the Dashboard Template

The `index.html` template now becomes a "shell". It contains the static parts of the page and empty containers (`<div>`s) that our JavaScript will fill with dynamic content.

**File to Edit:** `/app/templates/dashboard/index.html`

```html
{% extends "layouts/base.html" %}

{% block page_title %}Dashboard{% endblock %}

{% block content %}
    <header class="page-header">
        <div class="header-content">
            <h1><i class="fi fi-sr-dashboard"></i> LAMIS Dashboard</h1>
            <p class="tagline">Log Analysis and Monitoring System - Monitor and manage your security status</p>
        </div>
        <div class="header-actions">
            <button id="refresh-now-button" class="btn-primary">
                <i class="fi fi-br-refresh"></i> Refresh Now
            </button>
        </div>
    </header>

    {# Display any flashed error messages for manager connections #}
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

    {# NEW: Notification banner for new data, hidden by default #}
    <div id="new-data-notification" class="alert-info hidden" style="cursor: pointer;">
        <i class="fi fi-br-info"></i>
        New alert data is available. Click here to refresh the view.
    </div>

    <div class="stats-grid">
        {% set connected_managers = manager_statuses|selectattr(1, 'equalto', True)|list %}
        {% set total_managers = manager_statuses|length %}
        
        <div class="card stat-card">
            <h3>System Status</h3>
            {% if total_managers > 0 and connected_managers|length == total_managers %}
                <div class="value status-protected">Protected</div>
                <div class="meta">{{ connected_managers|length }} of {{ total_managers }} systems operational</div>
            {% elif total_managers == 0 %}
                <div class="value status-error">No Indexers</div>
                <div class="meta"><a href="{{ url_for('managers.manage') }}">Configure an indexer</a></div>
            {% else %}
                <div class="value status-error">Error</div>
                <div class="meta">{{ connected_managers|length }} of {{ total_managers }} systems operational</div>
            {% endif %}
        </div>

        <div class="card stat-card">
            <h3>Blocked IPs</h3>
            <div class="value">{{ blocked_ips_set|length }}</div>
            <div class="meta">Total IPs in blocklist</div>
        </div>
        <div class="card stat-card">
            <h3>Recent Alerts (24h)</h3>
            {# MODIFIED: This value will now be populated by JS #}
            <div class="value" id="recent-alerts-value">...</div>
            <div class="meta">From all connected managers</div>
        </div>
        <div class="card stat-card">
            <h3>Placeholder</h3>
            <div class="value">...</div>
            <div class="meta">...</div>
        </div>
    </div>

    <div class="activity-feed">
        <div class="activity-header">
            <h2><i class="fi fi-br-time-past"></i> Recent Activity</h2>
            <span class="activity-count" id="alert-count-span">Loading...</span>
            <div id="pagination-container" class="pagination">
                <!-- Pagination buttons will be inserted here by dashboard.js -->
            </div>
        </div>

        {# --- NEW: DYNAMIC CONTENT AREA --- #}
        {# This is where our JavaScript will inject the content. #}
        
        {# 1. Loading Spinner (shown initially) #}
        <div id="loading-spinner" class="empty-state">
            <i class="fi fi-br-spinner" style="animation: spin 1s linear infinite;"></i>
            <p>Loading Alerts...</p>
        </div>
        <style>@keyframes spin { from { transform: rotate(0deg); } to { rotate(360deg); } }</style>

        {# 2. The container for the list of alerts (hidden initially) #}
        <div id="activity-list-container" class="activity-list hidden">
            <!-- Alert items will be inserted here by dashboard.js -->
        </div>

        {# 3. The empty state message (shown if no alerts are found) #}
        <div id="empty-state" class="empty-state hidden">
            <i class="fi fi-br-triangle-warning" style="color: var(--warning-color, #ffc107);"></i>
            <p>No alerts found in the last 24 hours.</p>
            <small>This might mean everything is quiet, or it could indicate a problem with an agent or manager. Please verify your systems are reporting correctly.</small>
        </div>

        {# The pagination container has been moved to the activity header. #}
    </div>

    {# Helper to pass data to JS. This is a clean way to share server-side state. #}
    {# We pass the set of blocked IPs so the JS can correctly style alerts. #}
    <script id="blocked-ips-data" type="application/json">
        {{ blocked_ips_set|tojson }}
    </script>

    {# We still need the CSRF token from the block_form for our dynamic forms #}
    <div style="display: none;">
        {{ block_form.hidden_tag() }}
    </div>

{% endblock %}

{% block scripts %}
    {# NEW: Load our dashboard JavaScript as a module #}
    <script type="module" src="{{ url_for('static', filename='js/dashboard/main.js') }}"></script>
{% endblock %}
```

<details>
<summary><strong>Template Explanation</strong></summary>

*   **Removal of Loop:** The `{% for alert in alerts %}` loop is completely gone.
*   **Dynamic Placeholders:** We've added `div`s with specific IDs: `loading-spinner`, `activity-list-container`, and `empty-state`. Our JavaScript uses `document.getElementById()` to find these containers and fill them with content. We use a `hidden` CSS class to control which one is visible at any given time.
*   **Data Bridge (`<script type="application/json">`)**: We pass the `blocked_ips_set` to the frontend by embedding it as JSON inside a `<script>` tag. Our `state.js` reads this data. This is a clean and effective way to bootstrap server-side data into a client-side application.
*   **Module Script Tag:** At the bottom, we now load our `main.js` with `type="module"`. This is essential! It tells the browser to treat this file and its `import`s as modern ES modules.
</details>

### Step 4.3: Minor Layout and CSS Updates

We'll make small adjustments to our layout CSS and base template to accommodate the new header styles and pagination input fields.

**File to Edit:** `/app/static/css/layout.css` (Only the changed parts are shown for brevity, but you should replace the whole file). The main changes are to the `.page-header` and `.pagination` styles.

```css
/* app/static/css/layout.css */
:root {
    --sidebar-width: 260px;
    --header-height: 60px;
    --nav-icon-color: #7d8590;
    --nav-text-color: #e6edf3;
    --nav-hover-bg: rgba(172, 185, 201, 0.1);
    --nav-active-bg: #224675;
    --nav-active-border: #58a6ff;
}

html, body {
    height: 100%;
    overflow: hidden; /* Prevent body scrollbars */
}

.app-wrapper {
    display: flex;
    height: 100vh;
}

.sidebar {
    width: var(--sidebar-width);
    background-color: var(--background-color);
    border-right: 1px solid var(--border-color);
    padding: 20px 15px;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
}

.sidebar-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 10px 20px 10px;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 20px;
}

.sidebar-header .logo-icon {
    font-size: 28px;
    color: var(--primary-color);
}

.sidebar-header .logo-text h1 {
    font-size: 1.2em;
    margin: 0;
    color: var(--primary-text-color);
}

.sidebar-header .logo-text p {
    font-size: 0.8em;
    margin: 0;
    color: var(--secondary-text-color);
}

.sidebar-nav {
    flex-grow: 1;
}

.sidebar-nav ul {
    list-style: none;
    padding: 0;
    margin: 0;
}

.sidebar-nav ul li a {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 15px;
    border-radius: 6px;
    text-decoration: none;
    color: var(--nav-text-color);
    font-weight: 500;
    transition: background-color 0.2s ease, color 0.2s ease;
    margin-bottom: 5px;
    border-left: 3px solid transparent;
}

.sidebar-nav ul li a .nav-icon {
    font-size: 20px;
    color: var(--nav-icon-color);
    transition: color 0.2s ease;
}

.sidebar-nav ul li a:hover {
    background-color: var(--nav-hover-bg);
}

.sidebar-nav ul li a:hover .nav-icon {
    color: var(--primary-text-color);
}

.sidebar-nav ul li a.active {
    background-color: var(--nav-active-bg);
    color: white;
    border-left-color: var(--nav-active-border);
}

.sidebar-nav ul li a.active .nav-icon {
    color: white;
}

.sidebar-footer {
    padding: 15px;
    border-top: 1px solid var(--border-color);
}

.sidebar-footer a {
    display: flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    color: var(--secondary-text-color);
    transition: color 0.2s ease;
}

.sidebar-footer a:hover {
    color: var(--primary-text-color);
}

.main-content {
    flex-grow: 1;
    overflow-y: auto; /* Enable scrolling for content area only */
    background-color: #0d1117; /* Match body background */
}

.content-container {
    max-width: 1200px;
    margin: 40px auto;
    padding: 0 40px;
}

/* Page Header styles */
.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.page-header h1 {
    font-size: 2em;
    margin: 0 0 5px 0;
    display: flex;
    align-items: center;
    gap: 12px;
}
.page-header h1 i {
    color: var(--primary-color);
}
.page-header p {
    color: var(--secondary-text-color);
    margin-top: 0;
    max-width: 80ch;
}

.header-actions .btn-primary {
    background-color: var(--primary-color);
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.2s;
    display: flex;
    align-items: center;
    gap: 8px;
}

.header-actions .btn-primary:hover {
    background-color: #4a91e2;
}

.header-actions .btn-primary:disabled {
    background-color: var(--nav-active-bg);
    cursor: not-allowed;
}

.activity-header {
    display: flex;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 15px;
    margin-bottom: 15px;
}

.activity-header h2 {
    margin: 0;
    margin-right: auto; /* Pushes the other items to the right */
}

.activity-header .activity-count {
    color: var(--secondary-text-color);
    font-size: 0.9em;
    margin-right: 20px;
}

/* Table styles for manage pages */
.table-container {
    overflow-x: auto;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}
th, td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}
th {
    background-color: rgba(255, 255, 255, 0.05);
    font-size: 0.9em;
    text-transform: uppercase;
    color: var(--secondary-text-color);
}
td .ip-address {
    font-weight: bold;
    color: var(--primary-text-color);
}
.btn-unblock {
    background-color: var(--danger-color);
    color: white;
    border: none;
    padding: 6px 12px;
    font-size: 0.85em;
    border-radius: 4px;
    cursor: pointer;
    transition: background-color 0.2s;
}
.btn-unblock:hover {
    background-color: #d63031;
}

/* Pagination */
.pagination {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    padding: 0; /* Remove vertical padding */
    gap: 10px;
}
.btn-page {
    background: var(--surface-color);
    border: 1px solid var(--border-color);
    color: var(--primary-text-color);
    padding: 8px 12px;
    border-radius: 6px;
    text-decoration: none;
    font-size: 0.9em;
    cursor: pointer;
    transition: background-color 0.2s, border-color 0.2s;
}
.btn-page:not(:disabled):hover {
    background-color: var(--nav-hover-bg);
    border-color: var(--primary-color);
}
.btn-page:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}
.page-info {
    color: var(--secondary-text-color);
    font-size: 0.9em;
    display: flex;
    align-items: center;
    gap: 8px;
}
.page-input {
    width: 50px;
    padding: 4px 8px;
    background-color: var(--background-color);
    border: 1px solid var(--border-color);
    color: var(--primary-text-color);
    border-radius: 4px;
    text-align: center;
    font-size: 0.9em;
}
/* Hide the default number input arrows */
.page-input::-webkit-outer-spin-button,
.page-input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.page-input[type=number] {
  -moz-appearance: textfield;
}

/* Utility Classes */
.hidden {
    display: none !important;
}
```

**Files to Edit:** `/app/templates/layouts/base.html`

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

 `/app/templates/managers/manage.html` 
```html
{% extends "layouts/base.html" %}

{% block content %}
    <div class="page-header">
        <div class="header-content">
            <h1><i class="fi fi-sr-database"></i> Manage Wazuh Managers</h1>
            <p>View, add, or remove your Wazuh API connections.</p>
        </div>
        <div class="header-actions">
            <a href="{{ url_for('dashboard.index') }}" class="btn-secondary">
                <i class="fi fi-br-arrow-left"></i> Back to Dashboard
            </a>
        </div>
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
---

## Part 5: Tying It All Together

The final step is to make our Manager management pages trigger the new data refresh system. When an admin adds, edits, or deletes a Wazuh manager, we want the dashboard data to update immediately.

**File to Edit:** `/app/managers/routes.py`

```python
from flask import (
    render_template,
    redirect,
    url_for,
    flash,
    Blueprint,
    request,
    current_app,
)
from flask_login import login_required

from app.models import db
from app.models.wazuh import WazuhManager
from app.managers.forms import WazuhManagerForm
from app.managers.services import test_wazuh_connection
from app.tasks.services import trigger_data_refresh

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
            trigger_data_refresh(current_app._get_current_object())
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
                trigger_data_refresh(current_app._get_current_object())
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
                trigger_data_refresh(current_app._get_current_object())
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
    trigger_data_refresh(current_app._get_current_object())
    flash(f"Manager '{manager.name}' has been deleted.", "success")
    return redirect(url_for("managers.manage"))
```

<details>
<summary><strong>Code Explanation</strong></summary>

*   We import `trigger_data_refresh` from our new tasks service.
*   In every place where a manager configuration is successfully changed (add, edit, delete), we now call `trigger_data_refresh(current_app._get_current_object())`.
*   This sends the "REFRESH\_DATA" command to our scheduler via Redis Pub/Sub. The scheduler immediately runs the data fetching job.
*   The next time the user visits the dashboard, the cache will be fresh, reflecting the changes they just made. This provides a seamless and intuitive user experience.
*   `current_app._get_current_object()` is a way to pass the actual Flask `app` object, which our service function needs to access the application context.
</details>

---

## Final Review and Summary

Congratulations! You have successfully completed a major refactoring of the LAMIS application. Let's review the key improvements:

*   **Decoupling:** The slow, I/O-bound task of fetching data from Wazuh is now handled by a completely separate background process (`scheduler.py`). The Flask web application is now only responsible for serving fast API requests and rendering templates.
*   **Performance:** The dashboard now loads instantly. Data is read from the Redis cache, which is orders of magnitude faster than making live HTTP requests to Wazuh on every page load. Pagination is handled on the backend, minimizing the amount of data sent to the browser.
*   **User Experience:** The UI is now dynamic. It provides immediate feedback with loading spinners, handles errors gracefully, and can be refreshed without a full page reload. The new notification banner even tells the user when new data is available.
*   **Maintainability:** The code is now far more organized. We have clear separation of concerns with the new `api` and `tasks` modules, and the frontend logic is cleanly split into five single-purpose JavaScript files.

You've replaced a fragile, monolithic process with a robust, scalable, and message-driven architecture. This is a significant engineering achievement. Well done.
