import sys
import os

# Add your project directory to the Python path
# This assumes your .wsgi file is in the root of your project
# If your app.py is in a subdirectory (e.g., 'src'), adjust accordingly:
# project_home = u'/path/to/your/project/src'
project_home = os.path.dirname(os.path.abspath(__file__))
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import your Flask application instance
# Assuming your Flask app instance is named 'app' in app.py
from app import app as application
