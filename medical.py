import streamlit as st
import os
import hashlib
import csv
import time
from openai import OpenAI

# -------------------------------------------------------------------
# 1. CONFIGURATION & INITIALIZATION
# -------------------------------------------------------------------

# Hardcoded OpenAI API key (replace with your actual key)
OPENAI_API_KEY = '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'

client = OpenAI(api_key=OPENAI_API_KEY)
USERS_FILE = 'users.csv'

# -------------------------------------------------------------------
# 2. CUSTOM CSS STYLING
# -------------------------------------------------------------------

st.markdown("""
<style>
    /* Main background and text */
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #e9edf2 100%);
    }
    
    /* Chat message containers */
    .stChatMessage {
        border-radius: 15px;
        padding: 10px;
        margin-bottom: 10px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    
    /* User message styling */
    [data-testid="stChatMessage"]:has(div[data-testid="stMarkdown"]:contains("user")) {
        background-color: #dcf8c6;
        border-top-right-radius: 5px;
    }
    
    /* Assistant message styling */
    [data-testid="stChatMessage"]:has(div[data-testid="stMarkdown"]:contains("assistant")) {
        background-color: #ffffff;
        border-top-left-radius: 5px;
        border-left: 4px solid #2c7da0;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #2c3e50;
        color: white;
    }
    
    section[data-testid="stSidebar"] .stMarkdown, 
    section[data-testid="stSidebar"] .stTextInput label,
    section[data-testid="stSidebar"] .stButton button {
        color: white;
    }
    
    /* Buttons */
    .stButton button {
        background-color: #2c7da0;
        color: white;
        border-radius: 20px;
        transition: 0.3s;
        border: none;
        padding: 0.5rem 1rem;
    }
    .stButton button:hover {
        background-color: #1f5e7a;
        transform: scale(1.02);
    }
    
    /* Expander headers */
    .streamlit-expanderHeader {
        background-color: #34495e;
        color: white;
        border-radius: 10px;
    }
    
    /* Chat input */
    .stChatInput input {
        border-radius: 25px;
        border: 1px solid #2c7da0;
        padding: 10px 15px;
    }
    
    /* Titles */
    h1, h2, h3 {
        color: #2c3e50;
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* Caption */
    .stCaption {
        color: #7f8c8d;
        font-style: italic;
    }
    
    /* Success/Warning/Error boxes */
    .stAlert {
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 3. HELPER FUNCTIONS (AUTHENTICATION & USER MANAGEMENT)
# -------------------------------------------------------------------

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_users_file():
    """Create the users CSV file with headers if it does not exist."""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'password', 'name', 'surname', 'email'])

def user_exists(username):
    """Check if a username already exists (skip header row)."""
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        next(reader, None)  # skip header
        for row in reader:
            if row and row[0] == username:
                return True
    return False

def register_user(username, password, name, surname, email):
    """Register a new user."""
    if user_exists(username):
        return False
    hashed_password = hash_password(password)
    with open(USERS_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, hashed_password, name, surname, email])
    return True

def login_user(username, password):
    """Authenticate a user."""
    hashed_password = hash_password(password)
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        next(reader, None)  # skip header
        for row in reader:
            if row and row[0] == username and row[1] == hashed_password:
                return True
    return False

def get_user_info(username):
    """Retrieve user information (name, surname, email)."""
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        next(reader, None)  # skip header
        for row in reader:
            if row and row[0] == username:
                return {
                    'name': row[2],
                    'surname': row[3],
                    'email': row[4]
                }
    return None

def update_user_info(username, new_name, new_surname, new_email, new_password):
    """Update user information. If new_password is empty, keep old password."""
    updated = False
    rows = []
    with open(USERS_FILE, mode='r') as file:
        reader = csv.reader(file)
        header = next(reader, None)  # preserve header
        rows.append(header)
        for row in reader:
            if row and row[0] == username:
                hashed_password = hash_password(new_password) if new_password else row[1]
                rows.append([username, hashed_password, new_name, new_surname, new_email])
                updated = True
            else:
                rows.append(row)

    if updated:
        with open(USERS_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(rows)
    return updated

# -------------------------------------------------------------------
# 4. STREAMLIT PAGE CONFIGURATION & SESSION STATE
# -------------------------------------------------------------------

st.set_page_config(page_title="Medical Assistant", page_icon="🩺", layout="wide")
create_users_file()

# Initialize session state variables
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

# -------------------------------------------------------------------
# 5. AUTHENTICATION (LOGIN / REGISTRATION)
# -------------------------------------------------------------------

if not st.session_state.logged_in:
    st.sidebar.title("🔐 User Authentication")

    # Registration
    with st.sidebar.expander("📝 Register"):
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        reg_name = st.text_input("Name", key="reg_name")
        reg_surname = st.text_input("Surname", key="reg_surname")
        reg_email = st.text_input("Email", key="reg_email")
        if st.button("Register"):
            if register_user(reg_username, reg_password, reg_name, reg_surname, reg_email):
                st.success("User registered successfully. You can now log in.")
            else:
                st.error("Username already exists. Please choose a different one.")

    # Login
    with st.sidebar.expander("🔑 Login"):
        log_username = st.text_input("Username", key="log_username")
        log_password = st.text_input("Password", type="password", key="log_password")
        if st.button("Login"):
            if login_user(log_username, log_password):
                user_info = get_user_info(log_username)
                st.session_state.logged_in = True
                st.session_state.username = log_username
                st.session_state.name = user_info['name'].capitalize()
                st.session_state.surname = user_info['surname'].capitalize()
                st.session_state.email = user_info['email']
                st.success("Logged in successfully.")
                st.rerun()
            else:
                st.error("Invalid username or password.")

# -------------------------------------------------------------------
# 6. MAIN APPLICATION (LOGGED IN)
# -------------------------------------------------------------------

if st.session_state.logged_in:
    # Sidebar - User info and profile management
    st.sidebar.title(f"👋 Welcome, {st.session_state.name} {st.session_state.surname}")

    with st.sidebar.expander("📋 Your Information"):
        st.write(f"**Name:** {st.session_state.name} {st.session_state.surname}")
        st.write(f"**Email:** {st.session_state.email}")

    with st.sidebar.expander("✏️ Update Profile"):
        new_name = st.text_input("New Name", value=st.session_state.name, key="new_name")
        new_surname = st.text_input("New Surname", value=st.session_state.surname, key="new_surname")
        new_email = st.text_input("New Email", value=st.session_state.email, key="new_email")
        new_password = st.text_input("New Password (leave blank to keep unchanged)", type="password", key="new_password")
        if st.button("Update Profile"):
            if update_user_info(st.session_state.username, new_name, new_surname, new_email, new_password):
                st.session_state.name = new_name
                st.session_state.surname = new_surname
                st.session_state.email = new_email
                st.success("Profile updated successfully.")
            else:
                st.error("Update failed. Please try again.")

    # Sidebar - Bookmarks
    with st.sidebar.expander("🔖 Bookmarked Messages"):
        if not st.session_state.bookmarked_messages:
            st.info("No bookmarked messages yet. Click the 'Bookmark' button below an assistant response.")
        else:
            for idx, (question, answer) in enumerate(st.session_state.bookmarked_messages):
                with st.container():
                    st.markdown(f"**Q:** {question[:80]}...")
                    st.markdown(f"**A:** {answer[:120]}...")
                    if st.button("Remove", key=f"remove_{idx}"):
                        st.session_state.bookmarked_messages.pop(idx)
                        st.rerun()
                    st.divider()

    # Logout button
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.name = ''
        st.session_state.surname = ''
        st.session_state.email = ''
        st.session_state.chat_history = []
        st.session_state.bookmarked_messages = []
        st.success("Logged out successfully.")
        st.rerun()

    # -------------------------------------------------------------------
    # 7. CHAT INTERFACE
    # -------------------------------------------------------------------
    st.title("🩺 Medical Assistant")
    st.caption("Ask any medical question. For non-medical questions, I'll politely let you know I can't answer them.")

    # Clear chat button
    col1, col2 = st.columns([6, 1])
    with col2:
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()

    # Display chat history
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if question := st.chat_input(placeholder="e.g., What are the symptoms of the flu?"):
        # Append user message
        st.session_state.chat_history.append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)

        # Prepare system prompt - instructs assistant to refuse non-medical questions
        system_prompt = (
            "You are a medical assistant. You can ONLY answer questions related to diseases, their causes, "
            "drugs, treatments, symptoms, and general medical recommendations. "
            "If the user asks anything that is NOT medical (e.g., sports, weather, programming, history, politics, etc.), "
            "you must politely decline and state that you can only answer medical questions. "
            "Do not attempt to answer non-medical queries."
        )

        # Call OpenAI API
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    start_time = time.time()
                    # Convert chat history to OpenAI format (list of dicts with role and content)
                    messages = [{"role": "system", "content": system_prompt}]
                    for msg in st.session_state.chat_history:
                        messages.append({"role": msg["role"], "content": msg["content"]})
                    
                    chat_completion = client.chat.completions.create(
                        model="gpt-3.5-turbo",  # or "gpt-4" if you have access
                        messages=messages,
                        temperature=0.5,
                        max_tokens=1024,
                        top_p=1,
                        frequency_penalty=0,
                        presence_penalty=0,
                    )
                    response_time = time.time() - start_time
                    answer = chat_completion.choices[0].message.content

                    # Display the answer
                    st.markdown(answer)
                    st.caption(f"⏱️ Response time: {response_time:.2f} seconds")
                    
                    # Append assistant response to chat history
                    st.session_state.chat_history.append({"role": "assistant", "content": answer})

                    # Provide bookmark button for this response
                    col_bookmark, _ = st.columns([1, 5])
                    with col_bookmark:
                        if st.button("🔖 Bookmark this response", key=f"bookmark_{len(st.session_state.chat_history)}"):
                            st.session_state.bookmarked_messages.append((question, answer))
                            st.success("Message bookmarked!")

                except Exception as e:
                    st.error(f"An error occurred while contacting the OpenAI service: {str(e)}")

else:
    # Not logged in: welcome screen
    st.title("🩺 Welcome to the Medical Assistant")
    st.write("Please log in or register to interact with the AI medical assistant.")
    if os.path.exists("medical.png"):
        st.image("medical.png", use_column_width=True)
    st.write("""
        **Mission:** Provide users with a secure and personalized experience to access advanced AI-driven assistance for medical inquiries.
        
        **Features:**
        - Secure user authentication
        - Personalized profile management
        - AI-powered answers to medical questions (and polite refusal for non-medical questions)
        - Bookmark important answers
        - Full chat history
    """)
