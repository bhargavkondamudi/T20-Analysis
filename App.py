import streamlit as st
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

# Initialize session state variables safely
st.session_state.setdefault("logged_in", False)
st.session_state.setdefault("username", None)
st.session_state.setdefault("show_signup", False)  # Track whether to show signup page

# Load environment variables from Streamlit Secrets
DB_SERVER = st.secrets["DB_SERVER"]
DB_DATABASE = st.secrets["DB_DATABASE"]
DB_USERNAME = st.secrets["DB_USERNAME"]
DB_PASSWORD = st.secrets["DB_PASSWORD"]
driver = st.secrets["driver"]
user_table = st.secrets["user_table"]
Feedback_table = st.secrets["Feedback_table"]
user_session = st.secrets["user_session"]

# Database connection string
conn_str = (
    f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_DATABASE}?"
    f"driver={driver.replace(' ', '+')}"
)
engine = create_engine(conn_str)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define User model
class User(Base):
    __tablename__ = user_table
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

# Define Feedback model
class Feedback(Base):
    __tablename__ = Feedback_table
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False)
    feedback_date = Column(String(255), nullable=False)
    feedback_text = Column(Text, nullable=False)

# Define UserSession model to track login/logout times
class UserSession(Base):
    __tablename__ = user_session
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False)
    login_time = Column(String(255), nullable=False)
    logout_time = Column(String(255), nullable=True)

# Create tables if not exists
Base.metadata.create_all(bind=engine)

# Helper functions for password handling
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Password validation
def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char in '!@#$%^&*()-_=+[]{};:,.<>?/' for char in password):
        return False, "Password must contain at least one special character."
    return True, ""

# Login logic
def login():
    if not st.session_state["logged_in"]:
        st.title("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Login"):
                session = SessionLocal()
                user = session.query(User).filter(User.username == username).first()
                if user and check_password(password, user.password_hash):
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = username
                    st.session_state["show_signup"] = False

                    # Record login time
                    login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    user_session = UserSession(username=username, login_time=login_time, logout_time=None)
                    session.add(user_session)
                    session.commit()
                    session.close()

                    st.stop()
                else:
                    st.error("Invalid credentials")
                session.close()

        with col2:
            if st.button("Create Account"):
                st.session_state["show_signup"] = True
                st.stop()

# Signup logic
def signup():
    st.title("Create Account")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Sign Up"):
            valid, message = is_valid_password(password)
            if not valid:
                st.error(message)
                return

            if username and password:
                session = SessionLocal()
                existing_user = session.query(User).filter(User.username == username).first()
                if existing_user:
                    st.error("Username already exists! Please log in.")
                else:
                    new_user = User(username=username, password_hash=hash_password(password))
                    session.add(new_user)
                    session.commit()
                    st.session_state["show_signup"] = False
                    st.success("Account created successfully! Please log in.")
                session.close()

    with col2:
        if st.button("Back to Login"):
            st.session_state["show_signup"] = False
            st.stop()

# Feedback functionality with 500 character limit
def feedback_section():
    st.markdown("### Feedback")
    username = st.text_input("Your Username", value=st.session_state.get("username", ""), disabled=True)
    
    # Text area for feedback
    feedback = st.text_area("We value your feedback. Please share your thoughts below:", max_chars=500)

    if st.button("Submit Feedback"):
        if feedback.strip():
            feedback_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                session = SessionLocal()
                new_feedback = Feedback(username=username, feedback_date=feedback_date, feedback_text=feedback)
                session.add(new_feedback)
                session.commit()
                session.close()
                st.success("Thank you for your feedback!")
            except Exception as e:
                st.error(f"An error occurred while saving your feedback: {e}")
        else:
            st.error("Feedback cannot be empty. Please enter your details.")

# Main app logic
if st.session_state.get("logged_in"):
    st.title("Power BI Report Viewer")
    st.markdown(""" T20 Men World Cup Best 11 """)
    
    power_bi_url = "https://app.powerbi.com/view?r=eyJrIjoiMGUwOGUyY2YtMGFmMi00M2FlLWFkMTUtZTM2OTk2YmEwZTEyIiwidCI6ImFkNmQ2NjI0LTgyYTAtNDgyYS1hOWY1LTg5NmJiNzg3ZWUzOCJ9"
    st.markdown(
        f"""
        <iframe 
            src="{power_bi_url}" 
            width="100%" 
            height="350" 
            frameborder="0" 
            allowFullScreen="true">
        </iframe>
        """,
        unsafe_allow_html=True
    )

    feedback_section()

    if st.button("Logout"):
        session = SessionLocal()
        logout_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_session = session.query(UserSession).filter(
            UserSession.username == st.session_state["username"], UserSession.logout_time == None
        ).first()
        if user_session:
            user_session.logout_time = logout_time
            session.commit()
        session.close()

        st.session_state["logged_in"] = False
        st.info("You have been logged out.")
        st.stop()
else:
    if st.session_state.get("show_signup"):
        signup()
    else:
        login()
