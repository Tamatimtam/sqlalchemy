
### **LAMIS v2, Mission 1: The "For the Love of God, Just Work" Foundation**

Today, we're building the front door to our app. A secure, smart door that knows if it's the first time anyone's ever knocked. We'll build the setup page for the first admin and the regular login page for everyone after. No Wazuh, no OPNsense, just pure, solid Flask.

<details>
<summary><b>Step 1. 🏗️ The Workspace: Taming the Python Chaos</b></summary>

Before we write code, we need to set up our workshop. If you just throw all your tools in a pile on the floor, you'll never find your hammer. Same with code.

**1. Make a Folder:**
Duh. But seriously, let's keep it clean.

```bash
# Make the project folder
mkdir lamis_v2

# Go into it
cd lamis_v2
```

**2. The Virtual Environment (a.k.a. The Private Bubble):**
This is probably the most important, non-code thing you will do.

```bash
# This creates a folder named 'venv' in our project
python -m venv venv
```

> **🤔 Why We Do This (Seriously, Don't Skip This):**
> Imagine you have two Lego sets. One is a Star Wars X-Wing, the other is a Harry Potter castle. They both have little grey pieces, but they're *different* little grey pieces. If you dump them both into the same box, you'll go insane trying to build anything.
>
> A virtual environment (`venv`) is a separate box for each project. It keeps LAMIS's "Lego pieces" (its libraries) from getting mixed up with your other projects. It saves you from future tears. I promise.

**3. "Activate" the Bubble:**
You have to tell your terminal, "Hey, for now, I'm only working with the tools in *this* box."

*   On **macOS/Linux**:
    ```bash
    source venv/bin/activate
    ```
*   On **Windows**:
    ```bash
    .\venv\Scripts\activate
    ```
    You'll know it worked because your command prompt will change, usually with `(venv)` at the beginning.

**4. The `requirements.txt` (The Shopping List):**
This file lists every external tool our project needs.

Create a file named `requirements.txt` and put this inside:

```text
# requirements.txt

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
```

**5. Install the Stuff:**
Now we tell `pip` (Python's package installer) to go get everything on our list.

```bash
pip install -r requirements.txt
```

Boom. Our workshop is clean, organized, and has all the right tools.

</details>

<details>
<summary><b>Step 2. 🏛️ The Architecture: Why So Many Damn Folders?</b></summary>

I know, I know. It looks complicated. But trust me, this structure will save your sanity. We are building a system where every piece has one job. It's easier to find things, fix things, and add things later.

**Create this exact structure. Yes, all of it. Even the empty `__init__.py` files.**

```
/lamis_v2
|-- .env
|-- config.py
|-- run.py
|-- /app
    |-- __init__.py
    |-- /auth
    |   |-- __init__.py
    |   |-- forms.py
    |   |-- routes.py
    |-- /dashboard
    |   |-- __init__.py
    |   |-- routes.py
    |-- /models
    |   |-- __init__.py
    |   |-- user.py
    |   |-- state.py
    |-- /templates
        |-- /auth
        |   |-- login.html
        |   |-- setup.html
        |-- /dashboard
        |   |-- index.html
```

> **🤔 Jargon Buster: What the hell is all this?**
>
> *   `__init__.py`: This empty-looking file is a big deal. It tells Python, "This folder isn't just a folder; it's a 'package' of code that you can import from." The one in the main `/app` folder is extra special—it's where we'll build our app.
> *   `/auth`, `/dashboard`: These are **Blueprints**. Think of them as self-contained chapters in a book. The `auth` chapter contains everything about logging in, signing up, etc. The `dashboard` chapter will have the main pages. It's just organization.
> *   `/models`: This is where we define what our data looks like. A "model" is just a Python class that maps to a database table. `user.py` will describe the `users` table.
> *   `/templates`: All our HTML files go here. Flask knows to look in this folder automatically.
> *   `.env` & `config.py`: This is a critical security pattern. The `.env` file holds our actual passwords and secret keys. It's like the piece of paper with your bank password on it. The `config.py` file is the wallet that knows *how* to read that piece of paper, but doesn't store the password itself. **You never, ever, ever share your `.env` file.**
> *   `run.py`: A tiny script whose only job is to say "Hey Flask, start the app."

</details>

<details>
<summary><b>Step 3. ❤️ The Data Layer: Models, the ORM, and "Database Git"</b></summary>

Let's define our data. We'll use SQLAlchemy, which is an **ORM**.

> **🤔 Jargon Buster: ORM (Object-Relational Mapper)**
> An ORM is a godsend. It's a translator that lets you work with your database using Python objects instead of writing annoying, error-prone SQL.
>
> **Without an ORM:** `sql = "INSERT INTO users (username) VALUES ('orion')";`
> **With an ORM:** `new_user = User(username='orion'); db.session.add(new_user);`
>
> The ORM writes the SQL for you. It's safer, cleaner, and you get to stay in Python-land.

**1. Create the Model Files:**

*   **`app/models/__init__.py`**: This just creates the `db` object we'll use everywhere.
    ```python
    # app/models/__init__.py
    from flask_sqlalchemy import SQLAlchemy

    # Create the SQLAlchemy instance. It's like creating an empty toolbox.
    # We'll fill it with tools and connect it to our app later.
    db = SQLAlchemy()
    ```

*   **`app/models/user.py`**: Our blueprint for the `users` table.
    ```python
    # app/models/user.py
    from flask_login import UserMixin
    from werkzeug.security import generate_password_hash, check_password_hash
    from app.models import db

    # This class defines the 'users' table in our database.
    # UserMixin is a helper from Flask-Login that adds required login methods.
    class User(UserMixin, db.Model):
        # This explicitly names our table. Good practice.
        __tablename__ = 'users'

        # Defines the columns in our table.
        id = db.Column(db.Integer, primary_key=True) # The unique ID for each user.
        username = db.Column(db.String(64), index=True, unique=True, nullable=False)
        password_hash = db.Column(db.String(256)) # Longer to store the complex hash.

        # A method to take a plain password and store it securely.
        def set_password(self, password: str) -> None:
            self.password_hash = generate_password_hash(password)

        # A method to check if a submitted password matches the stored hash.
        def check_password(self, password: str) -> bool:
            return check_password_hash(self.password_hash, password)
    ```

*   **`app/models/state.py`**: Our special "Is the app set up?" switch.
    ```python
    # app/models/state.py
    from app.models import db

    class InitializationState(db.Model):
        __tablename__ = 'initialization_state'
        id = db.Column(db.Integer, primary_key=True)
        # This is our light switch. True = setup is done. False = setup is needed.
        setup_completed = db.Column(db.Boolean, default=False, nullable=False)
    ```

**2. Set up for Migrations:**
Now we need to connect these models to the actual database using **Flask-Migrate**.

> **🤔 Jargon Buster: Database Migrations**
> Imagine you build your app and release it. A month later, you realize you need to add an `email` column to your `users` table. What do you do? You can't just drop the table and remake it; you'd lose all your users!
>
> A migration is a small, version-controlled script that says "Hey database, I need you to add this `email` column." `Flask-Migrate` is the tool that automatically writes these scripts for you by comparing your Python models to the database. It's like **Git, but for your database structure.** It's how professionals manage database changes safely.

*   **`.env` file**: Create it in the root `lamis_v2` folder.
    ```ini
    # .env
    SECRET_KEY='this-is-a-secret-please-change-it'
    DATABASE_URL='postgresql://postgres:password@localhost:5432/orm_db'
    ```

*   **`config.py`**:
    ```python
    # config.py
    import os
    from dotenv import load_dotenv

    basedir = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(basedir, '.env'))

    class Config:
        SECRET_KEY = os.environ.get('SECRET_KEY')
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
        SQLALCHEMY_TRACK_MODIFICATIONS = False
    ```

*   **`app/__init__.py` (Temporary version for setup)**:
    ```python
    # app/__init__.py
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from flask_migrate import Migrate
    from config import Config

    db = SQLAlchemy()
    migrate = Migrate()

    def create_app(config_class=Config):
        app = Flask(__name__)
        app.config.from_object(config_class)

        db.init_app(app)
        migrate.init_app(app, db)

        # We need to import the models here so Flask-Migrate knows they exist.
        from app.models import user, state

        return app
    ```

*   **`run.py`**:
    ```python
    # run.py
    from app import create_app
    app = create_app()
    ```

**3. Run the Migration Commands:**
Make sure your PostgreSQL Docker container is running and your `venv` is active.

```bash
# Tell Flask where our app is.
# On macOS/Linux:
export FLASK_APP=run.py
# On Windows:
# set FLASK_APP=run.py

# COMMAND 1: Initialize the migration system.
# This creates the 'migrations' folder. You only ever run this once.
flask db init

# COMMAND 2: Generate the migration script.
# This compares your models to the DB and writes the "how-to" script.
flask db migrate -m "Initial migration with user and state tables."

# COMMAND 3: Apply the changes.
# This runs the script and actually creates the tables in PostgreSQL.
flask db upgrade
```

Your database is now live and matches your Python models.

</details>

<details>
<summary><b>Step 4. 🧠 The Brain: Assembling the App</b></summary>

Let's build the real logic now.

**1. The App Factory (`app/__init__.py`):**
This function is the recipe for building our app. It puts all the pieces together. Replace the temporary content of `app/__init__.py` with this final version.

```python
# app/__init__.py
from flask import Flask, request, redirect, url_for
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config
from app.models import db
from app.models.user import User
from app.models.state import InitializationState

# Create the extension instances here, in the global scope.
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_class=Config):
    # This is the "Application Factory" function.
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Now, connect our extensions to the specific app instance.
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # If a user tries to access a protected page but isn't logged in,
    # send them to the login page of our 'auth' blueprint.
    login_manager.login_view = 'auth.login'

    with app.app_context():
        # Import our blueprints.
        from .auth import routes as auth_routes
        from .dashboard import routes as dashboard_routes

        # Register them with the app. Now Flask knows about their routes.
        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(dashboard_routes.bp)

        # This function is required by Flask-Login. It's how it gets
        # the user object for a logged-in session.
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        # This is our gatekeeper. It runs before EVERY request.
        @app.before_request
        def check_initialization():
            # If the destination is an auth page or a static file (like CSS),
            # let it through. Otherwise, we'd have an infinite redirect loop.
            if request.endpoint and (request.endpoint.startswith('auth.') or request.endpoint == 'static'):
                return

            state = InitializationState.query.first()
            # If the state doesn't exist or the setup_completed flag is False...
            if not state or not state.setup_completed:
                # ...force the user to the setup page.
                return redirect(url_for('auth.setup'))
        
        # A helper command to create our initial state record.
        @app.cli.command("init-state")
        def init_state_command():
            if InitializationState.query.first():
                print("State record already exists.")
                return
            
            initial_state = InitializationState(setup_completed=False)
            db.session.add(initial_state)
            db.session.commit()
            print("✅ Database state initialized.")

        return app
```

Now, run this command to create that all-important state record: `flask init-state`.

**2. The Forms (`app/auth/forms.py`):**

> **🤔 Jargon Buster: Flask-WTF & CSRF**
> `Flask-WTF` helps us build forms. A `validator` is a rule, like "this field cannot be empty" or "these two password fields must match."
>
> The most important thing it does is protect against **CSRF (Cross-Site Request Forgery)**. Imagine you're logged into your bank. A hacker sends you an email with a link to a "cute cat picture." You click it. That page secretly contains a hidden form that submits a request to your bank's website to transfer money. Since you're already logged in, the bank thinks *you* sent the request.
>
> `Flask-WTF` stops this by putting a unique, secret, one-time-use token in every form (`{{ form.hidden_tag() }}`). When the form is submitted, Flask checks if the token is valid. The hacker's fake form won't have the right token, so the request is rejected. It's a simple but vital piece of security.

```python
# app/auth/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

class SetupForm(FlaskForm):
    username = StringField('Admin Username', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Complete Setup')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')
```

**3. The Routes (`app/auth/routes.py` and `app/dashboard/routes.py`):**
A route is the Python function that runs when you visit a specific URL.

*   `app/auth/routes.py`:
    ```python
    # app/auth/routes.py
    from flask import render_template, redirect, url_for, flash, Blueprint
    from flask_login import login_user, logout_user, login_required
    from app.models import db
    from app.models.user import User
    from app.models.state import InitializationState
    from app.auth.forms import SetupForm, LoginForm

    # This creates our "auth" blueprint. All routes here will be prefixed with /auth
    bp = Blueprint('auth', __name__, url_prefix='/auth')

    @bp.route('/setup', methods=['GET', 'POST'])
    def setup():
        state = InitializationState.query.first()
        if state and state.setup_completed