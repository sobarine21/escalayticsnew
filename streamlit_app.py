import streamlit as st
import google.generativeai as genai
import google_auth_oauthlib.flow
import googleapiclient.discovery
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
import base64
import json
import re
import os

# Configure AI Model
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])

# Streamlit App Setup
st.set_page_config(page_title="Escalytics", page_icon="📧", layout="wide")
st.title("⚡ Escalytics by EverTech")
st.write("Extract insights, root causes, and actionable steps from emails.")

# Google OAuth 2.0 Setup
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

# OAuth Credentials
CLIENT_ID = st.secrets["GOOGLE_CLIENT_ID"]
CLIENT_SECRET = st.secrets["GOOGLE_CLIENT_SECRET"]

if "credentials" not in st.session_state:
    st.session_state.credentials = None

# OAuth Authentication
def authenticate_user():
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        SCOPES
    )
    flow.redirect_uri = REDIRECT_URI
    auth_url, state = flow.authorization_url(prompt="consent")
    return auth_url, state, flow

# Fetch Emails from Gmail
def fetch_emails(creds):
    try:
        service = googleapiclient.discovery.build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = results.get("messages", [])

        email_texts = []
        for msg in messages:
            msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
            payload = msg_data.get("payload", {}).get("parts", [])
            email_body = ""

            for part in payload:
                if part.get("mimeType") == "text/plain":
                    email_body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                    break

            if email_body:
                email_texts.append(email_body)

        return email_texts

    except HttpError as error:
        st.error(f"An error occurred: {error}")
        return []

# Authenticate User
if not st.session_state.credentials:
    auth_url, state, flow = authenticate_user()
    st.markdown(f"[Click here to authenticate with Gmail]({auth_url})")
    state_token = st.text_input("Enter the authorization code after logging in:")

    if st.button("Submit Authorization Code"):
        try:
            flow.fetch_token(code=state_token)
            creds = flow.credentials
            st.session_state.credentials = creds
            st.success("Successfully authenticated!")
        except GoogleAuthError as e:
            st.error(f"Authentication failed: {e}")

# Fetch Emails
if st.session_state.credentials:
    st.subheader("Fetching your latest emails...")
    email_list = fetch_emails(st.session_state.credentials)

    if email_list:
        selected_email = st.selectbox("Select an email for analysis", email_list)
    else:
        st.write("No emails found or failed to fetch emails.")

# AI Analysis Functions
def get_ai_response(prompt, email_content):
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt + email_content[:1000])  # Limit to 1000 characters
        return response.text.strip()
    except Exception as e:
        return f"Error: {e}"

def get_sentiment(text):
    positive_words = ["happy", "good", "great", "excellent", "love"]
    negative_words = ["sad", "bad", "hate", "angry", "disappointed"]
    sentiment_score = sum([1 for word in text.split() if word.lower() in positive_words]) - sum([1 for word in text.split() if word.lower() in negative_words])
    return "Positive" if sentiment_score > 0 else "Negative" if sentiment_score < 0 else "Neutral"

def extract_key_phrases(text):
    return list(set(re.findall(r"\b[A-Za-z]{4,}\b", text)))

def detect_root_cause(text):
    return "Possible root cause: Lack of clear communication in the process."

def identify_culprit(text):
    if "manager" in text.lower():
        return "Culprit: The manager might be responsible."
    elif "team" in text.lower():
        return "Culprit: The team might be responsible."
    return "Culprit: Unknown"

# Display AI Analysis
if st.session_state.credentials and "selected_email" in locals() and selected_email:
    st.subheader("📊 AI Insights")

    summary = get_ai_response("Summarize the email in a concise format:\n\n", selected_email)
    sentiment = get_sentiment(selected_email)
    key_phrases = extract_key_phrases(selected_email)
    root_cause = detect_root_cause(selected_email)
    culprit = identify_culprit(selected_email)

    st.write(f"**Summary:** {summary}")
    st.write(f"**Sentiment:** {sentiment}")
    st.write(f"**Key Phrases:** {', '.join(key_phrases)}")
    st.write(f"**Root Cause:** {root_cause}")
    st.write(f"**Culprit Identification:** {culprit}")

    # Export Results
    export_data = {
        "Summary": summary,
        "Sentiment": sentiment,
        "Key Phrases": key_phrases,
        "Root Cause": root_cause,
        "Culprit": culprit
    }

    export_json = json.dumps(export_data, indent=4).encode("utf-8")
    st.download_button("Download Results as JSON", data=export_json, file_name="email_analysis.json", mime="application/json")
