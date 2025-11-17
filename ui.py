# ui.py (Single-File Application with Login, Registration, and Corrected Geolocation)

import streamlit as st
import pandas as pd
import sqlite3
import random
import bcrypt
from datetime import datetime

# FIX: Correct import for streamlit_geolocation component
try:
    from streamlit_geolocation import streamlit_geolocation
except ImportError:
    # Fallback/mock if the library is not installed
    def streamlit_geolocation():
        st.warning(f"Geolocation library missing. Please install: pip install streamlit-geolocation")
        # Ensure the fallback returns a dictionary that can be checked for location data
        return {'message': 'Geolocation component not available.'}

# --- Configuration ---
DB_NAME = 'civic_issues.db'
DEFAULT_ROLE = 'civic' # New users register as civic users

CATEGORIES = {
    1: "Pothole",
    2: "Graffiti",
    3: "Broken Streetlight",
    4: "Illegal Dumping",
    5: "Park Maintenance"
}

# --- ML Model Placeholders ---
def run_cnn_rnn_image_analysis(media_bytes):
    # Placeholder for CNN/RNN image analysis
    # Replace this with your actual image processing and ML model prediction logic
    if media_bytes:
        # Example: a more severe score if an image is provided
        return random.randint(3, 5) 
    return 0 # No image, no score from this model

def run_svm_nlp_text_analysis(description):
    # Placeholder for SVM/NLP text analysis
    # Replace this with your actual NLP model prediction logic
    if "critical" in description.lower() or "emergency" in description.lower() or "life-threatening" in description.lower():
        return 5
    elif "urgent" in description.lower() or "severe" in description.lower():
        return 4
    return 3 

# --- Database Management Functions ---

def init_db():
    """Initializes the SQLite database, tables, and default users."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # 1. Categories Table (unchanged)
    c.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            category_id INTEGER PRIMARY KEY,
            name TEXT UNIQUE
        )
    """)
    for id, name in CATEGORIES.items():
        c.execute("INSERT OR IGNORE INTO categories (category_id, name) VALUES (?, ?)", (id, name))
    
    # 2. Issues Table (Added 'status' options for tracking)
    c.execute("""
        CREATE TABLE IF NOT EXISTS issues (
            issue_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            category_id INTEGER,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            status TEXT DEFAULT 'Submitted', 
            guest_email TEXT,
            severity_score INTEGER DEFAULT 0,
            media_url TEXT,
            created_at TEXT
        )
    """)

    # 3. Users Table (NEW for login)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL 
        )
    """)
    
    # --- Create Default Users ---
    # Password: 'civic'
    civic_pass = bcrypt.hashpw('civic'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
              ('civic_user', civic_pass, 'civic'))
    
    # Password: 'admin'
    admin_pass = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
              ('admin_user', admin_pass, 'administrator'))
              
    conn.commit()
    conn.close()

@st.cache_resource
def get_db_connection():
    init_db()
    return sqlite3.connect(DB_NAME, check_same_thread=False) 

def register_new_user(username, password, role, _conn):
    """Adds a new user to the database with a hashed password."""
    if not username or not password:
        return False, "Username and password are required."
    
    try:
        c = _conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return False, "Username already exists."

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                  (username, hashed_password, role))
        _conn.commit()
        return True, "Registration successful. You can now log in."
        
    except sqlite3.Error as e:
        return False, f"Database error: {e}"

def verify_user(username, password, _conn):
    """Checks credentials against the database."""
    c = _conn.cursor()
    c.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
    user_data = c.fetchone()
    
    if user_data:
        hashed_password = user_data[0].encode('utf-8')
        role = user_data[1]
        
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return True, role
            
    return False, None

@st.cache_data(ttl=60)
def load_issues(_conn, role=None, user_id=None): 
    """Loads issues."""
    
    base_query = """
        SELECT 
            i.issue_id, i.title, i.status, i.severity_score, i.created_at, i.media_url,
            c.name AS category_name, i.latitude, i.longitude, i.description
        FROM issues i
        JOIN categories c ON i.category_id = c.category_id
    """
    
    query = base_query + " ORDER BY i.severity_score DESC, i.created_at DESC;"
    df = pd.read_sql(query, _conn) 
    return df.to_dict('records') 

def insert_issue(conn, issue_data):
    """Inserts a new issue into the database."""
    c = conn.cursor()
    c.execute("""
        INSERT INTO issues (title, description, category_id, latitude, longitude, guest_email, severity_score, media_url, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        issue_data['title'], 
        issue_data['description'], 
        issue_data['category_id'], 
        issue_data['latitude'], 
        issue_data['longitude'], 
        issue_data['guest_email'], 
        issue_data['severity_score'], 
        issue_data['media_url'], 
        datetime.now().isoformat()
    ))
    conn.commit()
    load_issues.clear() # Clear cache after insertion

def update_issue_status(conn, issue_id, new_status):
    """Updates the status of a specific issue."""
    c = conn.cursor()
    c.execute("UPDATE issues SET status = ? WHERE issue_id = ?", (new_status, issue_id))
    conn.commit()
    load_issues.clear() 

# --- VIEW RENDERING FUNCTIONS ---

def render_login_page(db_conn):
    """Renders the login/registration interface."""
    st.title("User Authentication")
    
    login_tab, register_tab = st.tabs(["Login", "Register"])
    
    # --- Login Tab ---
    with login_tab:
        st.subheader("Login to Your Account")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Login")

            if submitted:
                success, role = verify_user(username, password, db_conn)
                if success:
                    st.session_state['logged_in'] = True
                    st.session_state['role'] = role
                    st.session_state['username'] = username
                    st.rerun()
                else:
                    st.error("Invalid username or password.")

    # --- Registration Tab ---
    with register_tab:
        st.subheader(f"Register as a {DEFAULT_ROLE.capitalize()} User")
        st.info("Administrators cannot be registered through this page.")
        
        with st.form("register_form"):
            new_username = st.text_input("New Username", key="reg_username")
            new_password = st.text_input("New Password", type="password", key="reg_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password")
            
            reg_submitted = st.form_submit_button("Register")
            
            if reg_submitted:
                if new_password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    success, message = register_new_user(new_username, new_password, DEFAULT_ROLE, db_conn)
                    if success:
                        st.success(f"{message} Proceed to the Login tab.")
                    else:
                        st.error(f"Registration failed: {message}")

def render_civic_page(db_conn):
    """Renders the issue submission and tracking page for civic users."""
    st.title("🧑‍💻 Civic Issue Reporter - Submission & Tracking")

    # --- Sidebar for Logout ---
    with st.sidebar:
        st.header(f"Welcome, {st.session_state['username']}")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()
    
    tab1, tab2 = st.tabs(["Report New Issue", "Track My Issues"])

    # --- Tab 1: Report New Issue (Submission Form) ---
    with tab1:
        st.subheader("Report New Issue")
        
        # --- GEOLOCATION INPUT CONTROL ---
        st.markdown("### 🗺️ Location Details (Click button or edit fields)")
        
        # 1. Component for getting current location
        location_data = streamlit_geolocation() 
        
        # Read current state values. This logic defends against NoneType if state was somehow cleared.
        current_lat = st.session_state.get('last_lat')
        current_lon = st.session_state.get('last_lon')
        
        # FIX: Ensure current_lat/lon are 0.0 if they are None from session state.
        current_lat = current_lat if isinstance(current_lat, (int, float)) else 0.0
        current_lon = current_lon if isinstance(current_lon, (int, float)) else 0.0

        # 2. Update coordinates if the geolocation component returns new data
        if location_data and ('latitude' in location_data or 'longitude' in location_data):
            
            # Safely retrieve latitude and longitude, defaulting to current_lat/lon if the key is present but None.
            new_lat = location_data.get('latitude')
            new_lon = location_data.get('longitude')
            
            new_lat = new_lat if isinstance(new_lat, (int, float)) else current_lat
            new_lon = new_lon if isinstance(new_lon, (int, float)) else current_lon
            
            # Save new float values directly to session state.
            st.session_state['last_lat'] = new_lat
            st.session_state['last_lon'] = new_lon
            
            # This line is now safe because new_lat/lon are guaranteed to be valid floats
            st.success(f"Location Detected: Lat: {new_lat:.6f}, Lon: {new_lon:.6f}")
            
            # Update the local variables for use in the number inputs' value parameter
            current_lat = new_lat
            current_lon = new_lon
            
        elif location_data and 'message' in location_data:
            st.error(f"Location Error: {location_data['message']}")
        else:
            st.info("Click the default location button to auto-fill coordinates or enter them manually.")
            
        # 3. Display manual inputs, pre-filled with the GPS location (if available/persisted)
        loc_col1, loc_col2 = st.columns(2)
        with loc_col1:
            # Use the session state key as the widget key for binding and persistence.
            latitude_input = st.number_input(
                "Latitude", 
                format="%.6f", 
                value=current_lat, 
                step=0.0001, 
                key="last_lat" 
            )
        with loc_col2:
            # Use the session state key as the widget key for binding and persistence.
            longitude_input = st.number_input(
                "Longitude", 
                format="%.6f", 
                value=current_lon, 
                step=0.0001, 
                key="last_lon"
            )
        
        # -----------------------------

        with st.form(key='issue_form'):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Issue Title", max_chars=255, key="title_input") 
                description = st.text_area("Detailed Description", key="desc_input")
            with col2:
                category_name = st.selectbox("Category", options=list(CATEGORIES.values()), key="cat_select")
                guest_email = st.text_input("Your Email (Optional)", key="email_input")
            
            # Get the final coordinates directly from the session state (updated by the number inputs)
            latitude = st.session_state['last_lat']
            longitude = st.session_state['last_lon']

            # Media Upload
            st.markdown("#### 📸 Photo/Video Evidence")
            uploaded_file = st.file_uploader("Upload evidence", type=["jpg", "jpeg", "png"])

            submitted = st.form_submit_button("Submit Issue Report")

            if submitted:
                # --- Validation Check ---
                # Check that latitude/longitude were updated (either by GPS or manual entry)
                if not title or not description or (latitude == 0.0 and longitude == 0.0):
                    st.error("Please fill in the title, description, and obtain a valid location (Latitude/Longitude cannot both be 0.0).")
                    st.stop()
                
                # ML and DB Insertion Logic
                category_id = [k for k, v in CATEGORIES.items() if v == category_name][0]
                media_bytes = uploaded_file.read() if uploaded_file else None
                text_severity = run_svm_nlp_text_analysis(description)
                image_severity = run_cnn_rnn_image_analysis(media_bytes) if media_bytes else 0
                
                # Overall severity is the maximum score from text or image analysis
                overall_severity = max(text_severity, image_severity)
                
                media_url = f"local_media/{uploaded_file.name}" if uploaded_file else None
                
                new_issue_data = {
                    "title": title, "description": description, "category_id": category_id,
                    "latitude": latitude, "longitude": longitude, "guest_email": guest_email,
                    "severity_score": overall_severity, "media_url": media_url 
                }
                
                insert_issue(db_conn, new_issue_data)
                st.success(f"✅ Report Submitted! Priority: {overall_severity}. Status: Submitted.")
                st.rerun()

    # --- Tab 2: Track My Issues (Remains the same) ---
    with tab2:
        st.subheader("Track Your Submitted Issues")
        st.info("Current Statuses: Submitted, Viewed, In Progress, Resolved")
        
        issues = load_issues(db_conn, role='civic', user_id=None) 
        if issues:
            df = pd.DataFrame(issues)
            df['status_tracker'] = df['status'].apply(lambda x: f"▶️ {x}")
            
            track_df = df[['created_at', 'title', 'category_name', 'status_tracker', 'severity_score']]
            track_df.columns = ['Date', 'Title', 'Category', 'Current Status', 'Priority']
            st.dataframe(track_df, use_container_width=True, hide_index=True)
        else:
            st.info("No issues found.")


def render_admin_page(db_conn):
    """Renders the full complaint viewing and management page for administrators."""
    st.title("👑 Administrator Portal - Complaint Management")

    # --- Sidebar for Logout ---
    with st.sidebar:
        st.header(f"Welcome, {st.session_state['username']}")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

    st.subheader("Issues Overview")
    issues = load_issues(db_conn, role='administrator')
    
    if issues:
        df = pd.DataFrame(issues)
        df.rename(columns={'latitude': 'lat', 'longitude': 'lon'}, inplace=True)
        
        # Map View
        st.markdown("#### 🗺️ Issues Map")
        st.map(df[['lat', 'lon']], zoom=10)

        st.markdown("---")
        st.subheader("Issue Management Table")

        # Table View: Rename columns for display
        display_df = df.copy()
        display_df.rename(columns={'issue_id': 'ID', 'category_name': 'Category', 'severity_score': 'Priority', 'created_at': 'Date', 'title': 'Title', 'description': 'Description', 'status': 'Status'}, inplace=True)
        display_df = display_df[['ID', 'Date', 'Title', 'Description', 'Category', 'Status', 'Priority', 'lat', 'lon']]

        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # --- Status Update Form ---
        st.markdown("### Update Issue Status")
        with st.form("status_update_form"):
            # FIX: Use the original column name 'issue_id' to extract IDs from the original df
            valid_ids = df['issue_id'].tolist() if not df.empty else [1] 
            update_id = st.selectbox("Issue ID to Update", options=valid_ids)
            new_status = st.selectbox("New Status", options=['Submitted', 'Viewed', 'In Progress', 'Resolved'])
            update_button = st.form_submit_button("Update Status")

            if update_button:
                # FIX: Check against the original column name 'issue_id'
                if update_id in df['issue_id'].values: 
                    try:
                        update_issue_status(db_conn, update_id, new_status)
                        st.success(f"Status for Issue #{update_id} updated to '{new_status}'.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error updating status: {e}")
                else:
                    st.warning(f"Issue ID {update_id} not found.")

    else:
        st.info("No issues have been reported yet.")

# --- MAIN APP LOGIC ---

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'role' not in st.session_state:
    st.session_state['role'] = None
# Session state to store the last known coordinates (either GPS or manual)
# Initialize to 0.0 (float) to prevent NoneType errors on first run
if 'last_lat' not in st.session_state:
    st.session_state['last_lat'] = 0.0
if 'last_lon' not in st.session_state:
    st.session_state['last_lon'] = 0.0

# Initialize DB connection
db_conn = get_db_connection()

# --- Page Routing ---
if st.session_state['logged_in'] == False:
    render_login_page(db_conn)
elif st.session_state['role'] == 'civic':
    render_civic_page(db_conn)
elif st.session_state['role'] == 'administrator':
    render_admin_page(db_conn)