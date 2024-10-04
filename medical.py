import streamlit as st
import os
import hashlib
import csv
import time
from groq import Groq

# Define API key directly
GROQ_API_KEY = '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'

# Initialize Groq client
client = Groq(api_key=GROQ_API_KEY)

USERS_FILE = 'users.csv'

def hash_password(password):
    """Hash the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, name, surname, email):
    """Register a new user by appending their details to the CSV file."""
    hashed_password = hash_password(password)
    with open(USERS_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, hashed_password, name, surname, email])

def login_user(username, password):
    """Authenticate a user by checking username and password."""
    hashed_password = hash_password(password)
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username and row[1] == hashed_password:
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

def update_user_info(username, new_name, new_surname, new_email, new_password):
    """Update user information in the CSV file."""
    updated = False
    rows = []
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username:
                hashed_password = hash_password(new_password) if new_password else row[1]
                rows.append([username, hashed_password, new_name, new_surname, new_email])
                updated = True
            else:
                rows.append(row)

    if updated:
        with open(USERS_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(rows)

def create_users_file():
    """Create the users CSV file with headers if it does not exist."""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'password', 'name', 'surname', 'email'])

# Set page configuration
st.set_page_config(page_title="Medical Assistant", page_icon="medical.png")

# Create users file if it doesn't exist
create_users_file()

# User session state to track login status and user info
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'name' not in st.session_state:
    st.session_state.name = ''
if 'surname' not in st.session_state:
    st.session_state.surname = ''
if 'email' not in st.session_state:
    st.session_state.email = ''
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'bookmarked_messages' not in st.session_state:
    st.session_state.bookmarked_messages = []

# Authentication
if not st.session_state.logged_in:
    st.sidebar.title("User Authentication")

    # Registration
    with st.sidebar.expander("Register"):
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        reg_name = st.text_input("Name", key="reg_name")
        reg_surname = st.text_input("Surname", key="reg_surname")
        reg_email = st.text_input("Email", key="reg_email")
        if st.button("Register"):
            if not user_exists(reg_username):
                register_user(reg_username, reg_password, reg_name, reg_surname, reg_email)
                st.success("User registered successfully.")
            else:
                st.error("Username already exists.")

    # Login
    with st.sidebar.expander("Login"):
        log_username = st.text_input("Username", key="log_username")
        log_password = st.text_input("Password", type="password", key="log_password")
        if st.button("Login"):
            if login_user(log_username, log_password):
                st.session_state.logged_in = True
                st.session_state.username = log_username
                user_info = get_user_info(log_username)  # Fetch the user's info
                st.session_state.name = user_info['name'].capitalize()
                st.session_state.surname = user_info['surname'].capitalize()
                st.session_state.email = user_info['email']
                st.success("Logged in successfully.")
            else:
                st.error("Invalid username or password.")

# If logged in
if st.session_state.logged_in:
    st.sidebar.title(f"Welcome, {st.session_state.name} {st.session_state.surname}")

    # Profile Section
    with st.sidebar.expander("Your Information"):
        st.write(f"**Name:** {st.session_state.name} {st.session_state.surname}")
        st.write(f"**Email:** {st.session_state.email}")

    # Update Profile
    with st.sidebar.expander("Update Profile"):
        new_name = st.text_input("New Name", value=st.session_state.name, key="new_name")
        new_surname = st.text_input("New Surname", value=st.session_state.surname, key="new_surname")
        new_email = st.text_input("New Email", value=st.session_state.email, key="new_email")
        new_password = st.text_input("New Password", type="password", key="new_password")
        if st.button("Update Profile"):
            update_user_info(st.session_state.username, new_name, new_surname, new_email, new_password)
            st.session_state.name = new_name
            st.session_state.surname = new_surname
            st.session_state.email = new_email
            st.success("Profile updated successfully.")

    # Chat Interface
    st.title("Medical Assistant")
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat Input
    if question := st.chat_input(placeholder="Ask a medical question"):
        st.session_state.chat_history.append({"role": "user", "content": question})

        # Display user's message
        with st.chat_message("user"):
            st.markdown(question)

        # Create chat completion request
        start = time.process_time()
        chat_completion = client.chat.completions.create(
            messages=[{"role": "system", "content": "You are a medical assistant. You can only answer questions related to diseases, their causes, drugs, and recommendations."}] + st.session_state.chat_history,
            model="llama3-8b-8192",
            temperature=0.5,
            max_tokens=1024,
            top_p=1,
            stop=None,
            stream=False,
        )
        response_time = time.process_time() - start

        answer = chat_completion.choices[0].message.content

        # Display the response only if it meets medical criteria
        if any(term in answer.lower() for term in ['disease', 'cause', 'drug', 'recommendation']):
            st.session_state.chat_history.append({"role": "assistant", "content": answer})

            # Display assistant's response
            with st.chat_message("assistant"):
                st.markdown(answer)
        else:
            st.write("The response does not match the medical criteria.")

    # Logout
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.name = ''
        st.session_state.surname = ''
        st.session_state.email = ''
        st.session_state.chat_history = []
        st.session_state.bookmarked_messages = []
        st.success("Logged out successfully.")

else:
    st.title("Welcome to the Medical Assistant")
    st.write("Please log in to interact with the chatbot.")
    st.image("medical.png", use_column_width=True)
    st.write("The mission of this app is to provide users with a secure and personalized experience to access advanced AI-driven assistance for medical inquiries.")
