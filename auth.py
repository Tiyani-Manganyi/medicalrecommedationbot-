import os
import bcrypt
import csv
from dotenv import load_dotenv

load_dotenv()

USERS_FILE = 'users.csv'

def hash_password(password):
    """Hash the password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_password, provided_password):
    """Check if the provided password matches the stored hashed password."""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def register_user(username, password, name, surname, email):
    """Register a new user by appending their details to the CSV file."""
    hashed_password = hash_password(password)
    with open(USERS_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, hashed_password, name, surname, email])

def login_user(username, password):
    """Authenticate a user by checking username and password."""
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username and check_password(row[1], password):
                return True
    return False

def user_exists(username):
    """Check if a username already exists in the CSV file."""
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username:
                return True
    return False

def get_user_info(username):
    """Retrieve user information from the CSV file based on the username."""
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username:
                return {
                    'name': row[2],
                    'surname': row[3],
                    'email': row[4]
                }
    return None

def create_users_file():
    """Create the users CSV file with headers if it does not exist."""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'password', 'name', 'surname', 'email'])
