# Insurance Premium Predictor

This repository contains a simple Flask-based web app that loads a trained model (`insurance.pkl`) and provides a front-end form to predict insurance premiums.

Quick start

1. Create a virtual environment (recommended) and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

2. Ensure `insurance.pkl` is in the project root (same folder as `app.py`).

3. Run the app:

```powershell
python app.py
```

4. Open http://127.0.0.1:5000/ in your browser.

Notes

- The app uses an SQLite database `users.db` for user registration/login. The DB file is created automatically on first run.
- Templates are in the `templates/` folder: `index.html`, `login.html`, `registration.html`, `dashboard.html`, `result.html`.
- If you plan to deploy, replace the development server with a production WSGI server and secure the `secret_key`.
