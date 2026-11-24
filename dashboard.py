# ==========================================================
# SECUREWATCH - MINI SOC SECURITY MONITORING SYSTEM
# ==========================================================

import os
import smtplib
import psycopg2
import pandas as pd
import streamlit as st
import ipaddress
import requests
import resend
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# ==========================================================
# ABUSEIPDB - IP REPUTATION CHECKER
# ==========================================================

def check_ip_reputation(ip_address):

    try:
        ip_obj = ipaddress.ip_address(ip_address.strip())

        if not ip_obj.is_global:
            return {
                "error": "Private or reserved IP. Public reputation check is unavailable."
            }

        if not ABUSEIPDB_API_KEY:
            return {"error": "AbuseIPDB API key is missing."}

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": str(ip_obj),
            "maxAgeInDays": 90
        }

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        result = response.json()

        return result.get("data", {})

    except ValueError:
        return {"error": "Invalid IP address."}

    except requests.exceptions.RequestException as e:
        return {"error": f"API connection failed: {e}"}

print("AbuseIPDB API key loaded:", bool(ABUSEIPDB_API_KEY))
# ==========================================================
# IP INTELLIGENCE FUNCTION
# ==========================================================

def classify_ip(ip):

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "LOOPBACK"

        elif address.is_private:
            return "PRIVATE"

        elif address.is_reserved:
            return "RESERVED"

        elif address.is_global:
            return "PUBLIC"

        else:
            return "OTHER"

    except ValueError:
        return "INVALID"

from dotenv import dotenv_values
from email.message import EmailMessage
from streamlit_autorefresh import st_autorefresh


# ==========================================================
# 1. PAGE SETTINGS
# ==========================================================

st.set_page_config(
    page_title="SecureWatch SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)
# ==========================================================
# SECUREWATCH PROFESSIONAL CSS THEME
# ==========================================================

st.markdown("""
<style>

/* Main Dashboard Background */
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

/* Main Headings */
h1, h2, h3 {
    color: #38bdf8 !important;
    font-weight: 700 !important;
}

/* Metric Cards */
[data-testid="stMetric"] {
    background-color: #172554;
    border: 1px solid #2563eb;
    padding: 20px;
    border-radius: 12px;
}

/* Metric Values */
[data-testid="stMetricValue"] {
    color: #38bdf8;
    font-weight: bold;
}

/* Buttons */
.stButton > button {
    background-color: #2563eb;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 8px 18px;
    font-weight: bold;
}

.stButton > button:hover {
    background-color: #1d4ed8;
    color: white;
    border: 1px solid #38bdf8;
}

/* Data Tables */
[data-testid="stDataFrame"] {
    border: 1px solid #334155;
    border-radius: 10px;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #111827;
}

/* Dividers */
hr {
    border-color: #334155;
}
/* Sidebar Styling */
[data-testid="stSidebar"] {
    background: linear-gradient(
        180deg,
        #111827,
        #172554
    );
    border-right: 1px solid #2563eb;
}

/* Sidebar Text */
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] p {
    color: #e2e8f0 !important;
}

/* Sidebar Navigation */
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1,
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2,
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 {
    color: #38bdf8 !important;
}

/* Sidebar Input Fields */
[data-testid="stSidebar"] input {
    background-color: #1e293b;
    color: white;
    border: 1px solid #3b82f6;
    border-radius: 8px;
}
/* Success Messages */
[data-testid="stAlert"][kind="success"] {
    background-color: #064e3b;
    border: 1px solid #10b981;
    border-radius: 10px;
}

/* Warning Messages */
[data-testid="stAlert"][kind="warning"] {
    background-color: #78350f;
    border: 1px solid #f59e0b;
    border-radius: 10px;
}

/* Error Messages */
[data-testid="stAlert"][kind="error"] {
    background-color: #7f1d1d;
    border: 1px solid #ef4444;
    border-radius: 10px;
}

/* Info Messages */
[data-testid="stAlert"][kind="info"] {
    background-color: #172554;
    border: 1px solid #3b82f6;
    border-radius: 10px;
}
/* Professional Input Fields */
.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"] {
    background-color: #172554 !important;
    color: #ffffff !important;
    border: 1px solid #3b82f6 !important;
    border-radius: 8px !important;
}

/* Input Focus Effect */
.stTextInput input:focus,
.stTextArea textarea:focus {
    border: 1px solid #38bdf8 !important;
    box-shadow: 0 0 8px #2563eb !important;
}

/* Input Labels */
.stTextInput label,
.stTextArea label,
.stSelectbox label {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
}
/* ==================================================
   PROFESSIONAL TABLE DESIGN
   ================================================== */

/* Table Container */
[data-testid="stDataFrame"] {
    background-color: #111827 !important;
    border: 1px solid #2563eb !important;
    border-radius: 12px !important;
    overflow: hidden;
}

/* Table Header */
[data-testid="stDataFrame"] th {
    background-color: #1e3a8a !important;
    color: #ffffff !important;
    font-weight: bold !important;
}

/* Table Cells */
[data-testid="stDataFrame"] td {
    color: #e2e8f0 !important;
    background-color: #111827 !important;
}

/* Table Hover */
[data-testid="stDataFrame"] tr:hover td {
    background-color: #1e293b !important;
}
/* ==================================================
   PROFESSIONAL GRAPH DESIGN
   ================================================== */

/* Chart Container */
[data-testid="stVegaLiteChart"],
[data-testid="stArrowVegaLiteChart"],
[data-testid="stPyplot"],
[data-testid="stPlotlyChart"] {
    background-color: #111827 !important;
    border: 1px solid #2563eb !important;
    border-radius: 12px !important;
    padding: 12px !important;
}

/* Graph Section Spacing */
[data-testid="stElementContainer"] {
    border-radius: 10px;
}
/* ==================================================
   PROFESSIONAL SECTION HEADINGS
   ================================================== */

/* Section Headings */
h2, h3 {
    color: #38bdf8 !important;
    border-left: 4px solid #2563eb;
    padding-left: 12px;
    margin-top: 20px;
}

/* Main Dashboard Title */
h1 {
    color: #38bdf8 !important;
    font-size: 32px !important;
    font-weight: 800 !important;
    letter-spacing: 1px;
}

/* Section Divider */
hr {
    border: none;
    border-top: 1px solid #2563eb;
    margin-top: 25px;
    margin-bottom: 25px;
}
/* ==================================================
   PROFESSIONAL DOWNLOAD BUTTONS
   ================================================== */

/* Download Button */
.stDownloadButton > button {
    background: linear-gradient(
        90deg,
        #1d4ed8,
        #2563eb
    );
    color: white !important;
    border: 1px solid #38bdf8;
    border-radius: 10px;
    padding: 10px 20px;
    font-weight: bold;
    transition: 0.3s ease;
}

/* Download Button Hover */
.stDownloadButton > button:hover {
    background: linear-gradient(
        90deg,
        #0ea5e9,
        #2563eb
    );
    border: 1px solid #ffffff;
    box-shadow: 0 0 10px #2563eb;
    color: white !important;
}

/* ==================================================
   PROFESSIONAL EXPANDER DESIGN
   ================================================== */

/* Expander Container */
[data-testid="stExpander"] {
    background-color: #111827 !important;
    border: 1px solid #2563eb !important;
    border-radius: 12px !important;
    margin-bottom: 12px;
}

/* Expander Header */
[data-testid="stExpander"] summary {
    color: #38bdf8 !important;
    font-weight: bold !important;
}

/* Expander Content */
[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
    background-color: #0f172a !important;
    border-top: 1px solid #334155;
    padding: 15px;
}

/* ==================================================
   PROFESSIONAL CHECKBOX AND RADIO DESIGN
   ================================================== */

/* Checkbox Labels */
[data-testid="stCheckbox"] label {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
}

/* Radio Button Labels */
[data-testid="stRadio"] label {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
}

/* Checkbox and Radio Spacing */
[data-testid="stCheckbox"],
[data-testid="stRadio"] {
    margin-bottom: 10px;
}

/* Selection Control Hover */
[data-testid="stCheckbox"] label:hover,
[data-testid="stRadio"] label:hover {
    color: #38bdf8 !important;
}

/* ==================================================
   PROFESSIONAL TABS DESIGN
   ================================================== */

/* Tab Navigation */
.stTabs [data-baseweb="tab-list"] {
    background-color: #111827;
    border-radius: 10px;
    padding: 6px;
    gap: 8px;
}

/* Individual Tabs */
.stTabs [data-baseweb="tab"] {
    background-color: #172554;
    color: #e2e8f0 !important;
    border-radius: 8px;
    padding: 10px 18px;
}

/* Selected Tab */
.stTabs [aria-selected="true"] {
    background-color: #2563eb !important;
    color: #ffffff !important;
}

/* Tab Hover */
.stTabs [data-baseweb="tab"]:hover {
    background-color: #1e40af;
    color: #ffffff !important;
}

/* ==================================================
   PROFESSIONAL CODE BLOCK DESIGN
   ================================================== */

/* Code Block */
[data-testid="stCode"] {
    background-color: #111827 !important;
    border: 1px solid #2563eb !important;
    border-radius: 10px !important;
    padding: 12px !important;
}

/* Inline Code */
code {
    background-color: #1e293b !important;
    color: #38bdf8 !important;
    border-radius: 5px !important;
    padding: 3px 6px !important;
}

/* Status Text */
[data-testid="stMarkdownContainer"] strong {
    color: #38bdf8;
}

/* ==================================================
   PROFESSIONAL PROGRESS BAR DESIGN
   ================================================== */

/* Progress Bar Container */
[data-testid="stProgress"] {
    background-color: #172554 !important;
    border-radius: 10px !important;
    padding: 5px !important;
}

/* Progress Bar Fill */
[data-testid="stProgress"] > div > div > div {
    background: linear-gradient(
        90deg,
        #2563eb,
        #38bdf8
    ) !important;
    border-radius: 10px !important;
}

/* Progress Bar Height */
[data-testid="stProgress"] {
    height: 18px;
}

/* ==================================================
   PROFESSIONAL TOOLTIP DESIGN
   ================================================== */

/* Tooltip Styling */
[data-testid="stTooltip"] {
    background-color: #111827 !important;
    color: #ffffff !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 8px !important;
    padding: 8px 12px !important;
    box-shadow: 0 0 10px #2563eb;
}

/* Tooltip Text */
[data-testid="stTooltip"] p {
    color: #e2e8f0 !important;
    font-size: 13px !important;
}
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

h1, h2, h3 {
    color: #38bdf8 !important;
}

div[data-testid="stMetric"] {
    background-color: #172033;
    border: 1px solid #334155;
    padding: 18px;
    border-radius: 12px;
}

div[data-testid="stMetricLabel"] {
    color: #94a3b8;
}

div[data-testid="stMetricValue"] {
    color: #38bdf8;
}

.stButton button {
    border-radius: 8px;
    font-weight: bold;
}

/* ==================================================
   PROFESSIONAL FOOTER DESIGN
   ================================================== */

/* Footer Container */
footer {
    background-color: #111827 !important;
    border-top: 1px solid #2563eb !important;
}

/* Footer Text */
footer p {
    color: #94a3b8 !important;
    font-size: 13px !important;
}

/* Hide Streamlit Branding */
#MainMenu {
    visibility: hidden;
}

/* ==================================================
   PROFESSIONAL SCROLLBAR DESIGN
   ================================================== */

/* Scrollbar Width */
::-webkit-scrollbar {
    width: 9px;
    height: 9px;
}

/* Scrollbar Track */
::-webkit-scrollbar-track {
    background: #0b1120;
    border-radius: 10px;
}

/* Scrollbar Thumb */
::-webkit-scrollbar-thumb {
    background: #2563eb;
    border-radius: 10px;
    border: 2px solid #0b1120;
}

/* Scrollbar Hover */
::-webkit-scrollbar-thumb:hover {
    background: #38bdf8;
}

</style>
""", unsafe_allow_html=True)

# ==========================================================
# 2. LOAD PRIVATE SETTINGS FROM .env
# ==========================================================

folder = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(folder, ".env")
print("ENV PATH:", env_path)
print("ENV FILE EXISTS:", os.path.exists(env_path))
try:
    env_data = dict(st.secrets)
except Exception:
    env_data = dotenv_values(env_path)

EMAIL_ADDRESS = env_data.get("EMAIL_ADDRESS")
EMAIL_PASSWORD = env_data.get("EMAIL_PASSWORD")
ALERT_EMAIL = env_data.get("ALERT_EMAIL")
DB_PASSWORD = env_data.get("DB_PASSWORD")
ABUSEIPDB_API_KEY = env_data.get("ABUSEIPDB_API_KEY")
print("AbuseIPDB API key loaded:", bool(ABUSEIPDB_API_KEY))
st.title("🛡️ SecureWatch")



st.subheader("Mini SOC Security Monitoring System")

# Safe diagnostics: never print passwords or email addresses.
st.write("ENV file found:", os.path.isfile(env_path))
st.write("Gmail settings loaded:", bool(EMAIL_ADDRESS))
st.write("App password loaded:", bool(EMAIL_PASSWORD))
st.write("Alert recipient loaded:", bool(ALERT_EMAIL))
st.write("Database password loaded:", bool(DB_PASSWORD))


# ==========================================================
# 3. EMAIL ALERT FUNCTION
# ==========================================================
def send_security_email(ip, attempts, severity):

    try:
        resend.api_key = st.secrets["RESEND_API_KEY"]

        params = {
            "from": "SecureWatch <onboarding@resend.dev>",
            "to": [ALERT_EMAIL],
            "subject": "SecureWatch Security Alert",
            "text": f"""
SECUREWATCH SECURITY ALERT

Suspicious login activity detected!

IP Address: {ip}
Failed Login Attempts: {attempts}
Severity: {severity}

Please investigate this activity.

SecureWatch - Mini SOC Security Monitoring System
"""
        }

        resend.Emails.send(params)

        return True, "Security email sent successfully!"

    except Exception as e:
        return False, str(e)

# ==========================================================
# 4. TEST EMAIL BUTTON
# ==========================================================

if st.button("📧 Test Gmail Connection"):

    success, message = send_security_email(
        "192.168.1.100",
        5,
        "HIGH"
    )

    if success:
        st.success(message)
    else:
        st.error(message)


# ==========================================================
# 5. AUTOMATIC DASHBOARD REFRESH
# ==========================================================

st_autorefresh(
    interval=30000,
    key="securewatch_refresh"
)
st.success("🟢 LIVE MONITORING ACTIVE — Auto-refresh every 30 seconds")


# ==========================================================
# 6. CONNECT TO POSTGRESQL
# ==========================================================

if not DB_PASSWORD:
    st.error("PostgreSQL password is missing in .env.")
    st.stop()

try:
    DATABASE_URL = st.secrets["DATABASE_URL"]

    connection = psycopg2.connect(DATABASE_URL)

    query = """
        SELECT ip_address, status, login_time
        FROM login_logs
        ORDER BY login_time DESC;
    """

    df = pd.read_sql_query(query, connection)
    connection.close()

except Exception as e:
    st.error("Cloud database connection failed.")
    st.code(str(e))
    st.stop()
# ==========================================================
# 7. LOGIN STATISTICS
# ==========================================================


total_logins = len(df)

if total_logins > 0:

    failed_logins = (
        df["status"].astype(str).str.lower() == "failed"
    ).sum()

    successful_logins = (
        df["status"].astype(str).str.lower() == "success"
    ).sum()

else:
    failed_logins = 0
    successful_logins = 0


# ==========================================================
# 8. FAILED LOGIN COUNTS BY IP
# ==========================================================
failed_df = df[
    df["status"].astype(str).str.lower() == "failed"
].copy()

if not failed_df.empty:

    ip_counts = (
        failed_df.groupby("ip_address")
        .size()
        .reset_index(name="Failed Attempts")
    )

    last_seen = (
        failed_df.groupby("ip_address")["login_time"]
        .max()
        .reset_index(name="Last Failed Login")
    )

    ip_counts = ip_counts.merge(
        last_seen,
        on="ip_address"
    )

    ip_counts = ip_counts.rename(
        columns={"ip_address": "IP Address"}
    )

else:
    ip_counts = pd.DataFrame(
        columns=[
            "IP Address",
            "Failed Attempts",
            "Last Failed Login"
        ]
    )
# ==========================================================
# TOP 10 ATTACKING IP ADDRESSES
# ==========================================================

st.divider()
st.header("🎯 Top 10 Attacking IP Addresses")

if not ip_counts.empty:

    top_attacking_ips = (
        ip_counts
        .sort_values(
            by="Failed Attempts",
            ascending=False
        )
        .head(10)
    )

    st.bar_chart(
        top_attacking_ips,
        x="IP Address",
        y="Failed Attempts"
    )

else:

    st.info("No failed login attacks found.")
# ==========================================================
# SOC OVERVIEW
# ==========================================================

st.divider()
st.header("📊 SOC Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Login Attempts", total_logins)
col2.metric("Successful Logins", successful_logins)
col3.metric("Failed Logins", failed_logins)
col4.metric("Suspicious IP Addresses", len(ip_counts))


# ==========================================================
# ATTACK PATTERN DETECTION
# ==========================================================

st.divider()
st.header("🚨 Attack Pattern Detection")

if not failed_df.empty:

    attack_df = failed_df.copy()

    attack_df["login_time"] = pd.to_datetime(
        attack_df["login_time"],
        errors="coerce"
    )

    attack_df = attack_df.dropna(
        subset=["login_time"]
    )

    attack_patterns = []

    for ip, group in attack_df.groupby("ip_address"):

        group = group.sort_values("login_time")

        five_minute_counts = (
            group.set_index("login_time")["status"]
            .rolling("5min")
            .count()
        )

        max_attempts = int(five_minute_counts.max())

        if max_attempts >= 5:

            attack_patterns.append({
                "IP Address": ip,
                "Failed Attempts in 5 Minutes": max_attempts,
                "Attack Type": "Possible Brute Force"
            })

    if attack_patterns:

        attack_pattern_df = pd.DataFrame(attack_patterns)

        st.warning("Possible brute-force attack detected!")

        st.dataframe(
            attack_pattern_df,
            hide_index=True,
            width="stretch"
        )

    else:
        st.success("No brute-force attack pattern detected.")

else:
    st.info("No failed login activity available.")


   
# ==========================================================
# 9. SECURITY SEVERITY
# ==========================================================

def get_severity(attempts):

    if attempts >= 5:
        return "HIGH"

    elif attempts >= 3:
        return "MEDIUM"

    else:
        return "LOW"


if not ip_counts.empty:

    ip_counts["Severity"] = (
        ip_counts["Failed Attempts"].apply(get_severity)
    )

security_alerts = ip_counts.to_dict("records")
# ==========================================================
# AUTOMATIC ABUSEIPDB IP REPUTATION CHECK
# ==========================================================

if not ip_counts.empty:

    reputation_scores = []
    reputation_reports = []
    reputation_levels = []
    reputation_countries = []

    for ip in ip_counts["IP Address"]:

        reputation = check_ip_reputation(str(ip))

        if "error" in reputation:

            st.warning(
                f"AbuseIPDB check failed for {ip}: {reputation['error']}"
            )

            reputation_scores.append("Unavailable")
            reputation_reports.append("Unavailable")
            reputation_levels.append("Unknown")
            reputation_countries.append("Unknown")

        else:

            score = int(reputation.get("abuseConfidenceScore", 0))
            reports = int(reputation.get("totalReports", 0))
            country = reputation.get("countryCode") or "Unknown"
            reputation_countries.append(country)

            if score >= 75:
                level = "HIGH"
            elif score >= 25:
                level = "MEDIUM"
            else:
                level = "LOW"

            reputation_scores.append(score)
            reputation_reports.append(reports)
            reputation_levels.append(level)

    ip_counts["AbuseIPDB Score"] = reputation_scores
    ip_counts["AbuseIPDB Reports"] = reputation_reports
    ip_counts["IP Reputation"] = reputation_levels
    ip_counts["Country"] = reputation_countries
# ==========================================================
# IP ATTACK RISK SCORE
# ==========================================================

def calculate_risk_score(row):

    failed_attempts = int(row["Failed Attempts"])

    abuse_score = pd.to_numeric(
        row["AbuseIPDB Score"],
        errors="coerce"
    )

    if pd.isna(abuse_score):
        abuse_score = 0

    login_risk = min(failed_attempts * 5, 50)

    reputation_risk = abuse_score * 0.5

    total_risk = login_risk + reputation_risk

    return min(round(total_risk), 100)


ip_counts["Risk Score"] = ip_counts.apply(
    calculate_risk_score,
    axis=1
)
# ==========================================================
# RISK LEVEL CLASSIFICATION
# ==========================================================

def classify_risk(score):

    if score >= 76:
        return "CRITICAL"

    elif score >= 51:
        return "HIGH"

    elif score >= 26:
        return "MEDIUM"

    else:
        return "LOW"


ip_counts["Risk Level"] = (
    ip_counts["Risk Score"].apply(classify_risk)
)
# ==========================================================
# OVERALL RISK DISTRIBUTION
# ==========================================================

st.divider()
st.subheader("📊 Overall Risk Distribution")

if not ip_counts.empty:

    risk_counts = (
        ip_counts["Risk Level"]
        .value_counts()
        .reindex(
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            fill_value=0
        )
    )

    st.bar_chart(risk_counts)

else:

    st.info("No risk data available.")
# ==========================================================
# COUNTRY-WISE ATTACK ANALYSIS
# ==========================================================

st.divider()
st.subheader("🌍 Country-wise Attack Analysis")

if not ip_counts.empty:

    country_attacks = (
        ip_counts.groupby("Country")["Failed Attempts"]
        .sum()
        .reset_index()
        .sort_values(
            by="Failed Attempts",
            ascending=False
        )
    )

    st.bar_chart(
        country_attacks,
        x="Country",
        y="Failed Attempts"
    )

else:
    st.info("No country-wise attack data available.")
# ==========================================================
# THREAT INTELLIGENCE SUMMARY
# ==========================================================

st.divider()
st.header("🛡️ Threat Intelligence Summary")

total_ips_checked = len(ip_counts)

high_risk_ips = sum(
    1 for level in reputation_levels if level == "HIGH"
)

medium_risk_ips = sum(
    1 for level in reputation_levels if level == "MEDIUM"
)

low_risk_ips = sum(
    1 for level in reputation_levels if level == "LOW"
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total IPs Checked", total_ips_checked)
col2.metric("HIGH Risk", high_risk_ips)
col3.metric("MEDIUM Risk", medium_risk_ips)
col4.metric("LOW Risk", low_risk_ips)
# ==========================================================
# HIGH-RISK IP INVESTIGATION LIST
# ==========================================================

st.divider()
st.subheader("🚨 High-Risk IP Investigation List")

if not ip_counts.empty:

    high_risk_df = ip_counts[
        ip_counts["IP Reputation"] == "HIGH"
    ].copy()

    if not high_risk_df.empty:

        st.dataframe(
            high_risk_df[
                [
                    "IP Address",
                    "Failed Attempts",
                    "AbuseIPDB Score",
                    "AbuseIPDB Reports",
                    "Country",
                    "Risk Score",
                    "Risk Level",
                ]
            ],
            hide_index=True,
            width="stretch"
        )

    else:
        st.success("No HIGH-risk IP addresses found.")

else:
    st.info("No IP information available.")

st.subheader("IP Reputation Distribution")

threat_data = pd.DataFrame({
    "Threat Level": ["HIGH", "MEDIUM", "LOW"],
    "IP Count": [
        high_risk_ips,
        medium_risk_ips,
        low_risk_ips
    ]
})

st.bar_chart(
    threat_data,
    x="Threat Level",
    y="IP Count"
)
# ==========================================================
# SECURITY INCIDENT PRIORITY DASHBOARD
# ==========================================================

st.divider()
st.subheader("🚨 Security Incident Priority Dashboard")

if not ip_counts.empty:

    priority_counts = (
        ip_counts["Risk Level"]
        .value_counts()
        .reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            fill_value=0
        )
    )

    st.bar_chart(priority_counts)

else:

    st.info("No security incidents available.")
# ==========================================================
# SAVE SECURITY ALERTS INTO POSTGRESQL
# =========================================================
try:
    history_connection = psycopg2.connect(
        st.secrets["DATABASE_URL"]
    )

    history_cursor = history_connection.cursor()

    for alert in security_alerts:

        history_cursor.execute("""
            INSERT INTO security_alert_history
            (ip_address, failed_attempts, severity)
            VALUES (%s, %s, %s)
            ON CONFLICT ON CONSTRAINT unique_security_alert
            DO NOTHING;
        """, (
            str(alert["IP Address"]),
            int(alert["Failed Attempts"]),
            alert["Severity"]
        ))

    history_connection.commit()

    history_cursor.close()
    history_connection.close()

    st.success("Security alerts saved in PostgreSQL!")

except Exception as e:
    st.error("Alert history saving failed.")
    st.code(str(e))


# ==========================================================
# AUTOMATIC HIGH ALERT EMAIL - DUPLICATE PREVENTION
# ==========================================================

for alert in security_alerts:

    if alert["Severity"] == "HIGH":

        ip = str(alert["IP Address"])
        attempts = int(alert["Failed Attempts"])
        severity = alert["Severity"]

        try:
            # Check email status in PostgreSQL
            with psycopg2.connect(
                st.secrets["DATABASE_URL"]
            ) as connection:

                with connection.cursor() as cursor:

                    cursor.execute("""
                        SELECT email_sent
                        FROM security_alert_history
                        WHERE ip_address = %s
                        AND failed_attempts = %s
                        AND severity = %s;
                    """, (ip, attempts, severity))

                    result = cursor.fetchone()

            # Send email only if not already sent
            if result is not None and result[0] is False:

                success, message = send_security_email(
                    ip,
                    attempts,
                    severity
                )

                if success:

                    with psycopg2.connect(
                        st.secrets["DATABASE_URL"]
                    ) as connection:

                        with connection.cursor() as cursor:

                            cursor.execute("""
                                UPDATE security_alert_history
                                SET email_sent = TRUE
                                WHERE ip_address = %s
                                AND failed_attempts = %s
                                AND severity = %s;
                            """, (ip, attempts, severity))

                    st.success(f"Email sent for {ip}!")

                else:
                    st.warning(f"Email failed for {ip}: {message}")

            elif result is not None and result[0] is True:

                st.info(f"Duplicate email prevented for {ip}.")

        except Exception as e:

            st.error(f"Email tracking error for {ip}")
            st.code(str(e))

# ==========================================================
# 12. SEVERITY SUMMARY
# ==========================================================

high_count = sum(
    1 for a in security_alerts if a["Severity"] == "HIGH"
)

medium_count = sum(
    1 for a in security_alerts if a["Severity"] == "MEDIUM"
)

low_count = sum(
    1 for a in security_alerts if a["Severity"] == "LOW"
)

st.header("🚨 Security Severity Summary")

col1, col2, col3 = st.columns(3)

col1.metric("HIGH Alerts", high_count)
col2.metric("MEDIUM Alerts", medium_count)
col3.metric("LOW Alerts", low_count)


# ==========================================================
# 13. LOGIN ANALYTICS CHART
# ==========================================================

st.divider()
st.header("📈 Login Analytics")

# ==========================================================
# ATTACK TIMELINE
# ==========================================================

st.divider()
st.header("⏱️ Attack Timeline")

if not df.empty:

    timeline_df = df.copy()

    timeline_df["login_time"] = pd.to_datetime(
        timeline_df["login_time"],
        errors="coerce"
    )

    failed_timeline = timeline_df[
        timeline_df["status"].astype(str).str.lower() == "failed"
    ].dropna(subset=["login_time"])

    if not failed_timeline.empty:

        daily_attacks = (
            failed_timeline
            .set_index("login_time")
            .resample("D")
            .size()
            .reset_index(name="Failed Attempts")
        )

        st.subheader("Daily Failed Login Attempts")

        st.line_chart(
            daily_attacks,
            x="login_time",
            y="Failed Attempts"
        )

        st.subheader("Recent Failed Login Activity")

        st.dataframe(
            failed_timeline[
                ["ip_address", "login_time"]
            ].head(20),
            hide_index=True,
            width="stretch"
        )

    else:
        st.info("No failed login activity found.")

else:
    st.info("No login history available.")

analytics = pd.DataFrame({
    "Login Type": ["Failed", "Successful"],
    "Count": [int(failed_logins), int(successful_logins)]
})

st.bar_chart(
    analytics,
    x="Login Type",
    y="Count"
)
# ==========================================================
# HOURLY FAILED LOGIN TREND
# ==========================================================

st.divider()
st.subheader("⏰ Hourly Failed Login Trend")

if not failed_timeline.empty:

    hourly_attacks = (
        failed_timeline
        .set_index("login_time")
        .resample("h")
        .size()
        .reset_index(name="Failed Attempts")
    )

    st.line_chart(
        hourly_attacks,
        x="login_time",
        y="Failed Attempts"
    )

else:

    st.info("No failed login data available for hourly analysis.")
# ==========================================================
# RECENT SECURITY ACTIVITY FEED
# ==========================================================

st.divider()
st.subheader("🕒 Recent Security Activity Feed")

if not timeline_df.empty:

    recent_activity = timeline_df.copy()

    recent_activity = recent_activity.sort_values(
        by="login_time",
        ascending=False
    )

    recent_activity["status"] = (
        recent_activity["status"].astype(str).str.upper()
    )

    recent_activity = recent_activity.rename(
        columns={
            "ip_address": "IP Address",
            "status": "Login Status",
            "login_time": "Login Time"
        }
    )

    st.dataframe(
        recent_activity[
            ["IP Address", "Login Status", "Login Time"]
        ].head(20),
        hide_index=True,
        width="stretch"
    )

else:
    st.info("No recent security activity available.")

# ==========================================================
# 14. FAILED LOGIN ATTEMPTS BY IP
# ==========================================================

st.header("🌐 Failed Login Attempts by IP")

if not ip_counts.empty:

    st.bar_chart(
        ip_counts.set_index("IP Address")["Failed Attempts"]
    )

else:
    st.info("No failed login attempts found.")


# ==========================================================
# 15. SECURITY ALERTS TABLE
# ==========================================================

st.divider()
st.header("🚨 Security Alerts")
# ==========================================================
# THREAT LEVEL VISUALIZATION
# ==========================================================

st.divider()
st.subheader("📊 Threat Level Distribution")

if not ip_counts.empty:

    severity_counts = ip_counts["Severity"].value_counts()
    high_alerts = int((ip_counts["Severity"] == "HIGH").sum())
    medium_alerts = int((ip_counts["Severity"] == "MEDIUM").sum())
    low_alerts = int((ip_counts["Severity"] == "LOW").sum())
    summary1, summary2, summary3 = st.columns(3)

    summary1.metric("🔴 HIGH Alerts", high_alerts)

    summary2.metric("🟠 MEDIUM Alerts", medium_alerts)

    summary3.metric("🟢 LOW Alerts", low_alerts)

    st.bar_chart(severity_counts)

else:
    st.info("No security alerts available.")
if not ip_counts.empty:
        # Add IP Intelligence classification
    ip_counts["IP Type"] = (
        ip_counts["IP Address"]
        .astype(str)
        .apply(classify_ip)
    )
    search_ip = st.text_input("🔍 Search IP Address")

    severity_filter = st.selectbox(
        "Filter by Severity",
        ["ALL", "HIGH", "MEDIUM", "LOW"]
    )

    filtered_alerts = ip_counts.copy()

    if search_ip:
        filtered_alerts = filtered_alerts[
            filtered_alerts["IP Address"]
            .astype(str)
            .str.contains(search_ip, case=False, na=False)
        ]

    if severity_filter != "ALL":
        filtered_alerts = filtered_alerts[
            filtered_alerts["Severity"] == severity_filter
        ]

        # FIX MIXED ABUSEIPDB DATA TYPES

    display_alerts = filtered_alerts.copy()

    if "AbuseIPDB Score" in display_alerts.columns:
        display_alerts["AbuseIPDB Score"] = (
            display_alerts["AbuseIPDB Score"].astype(str)
        )

    if "AbuseIPDB Reports" in display_alerts.columns:
        display_alerts["AbuseIPDB Reports"] = (
            display_alerts["AbuseIPDB Reports"].astype(str)
        )


    csv_data = filtered_alerts.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Security Report",
        data=csv_data,
        file_name="SecureWatch_Security_Report.csv",
        mime="text/csv"
    )
    # ==========================================================
# ATTACK SEVERITY RANKING
# ==========================================================

st.divider()
st.subheader("🏆 Attack Severity Ranking")

if not filtered_alerts.empty:

    ranking_df = (
        filtered_alerts
        .sort_values(
            by="Failed Attempts",
            ascending=False
        )
        .head(10)
        .reset_index(drop=True)
    )

    ranking_df.insert(
        0,
        "Rank",
        range(1, len(ranking_df) + 1)
    )

    st.dataframe(
        ranking_df[
            ["Rank", "IP Address", "Failed Attempts", "Severity"]
        ],
        hide_index=True,
        width="stretch"
    )

else:
    st.info("No security risks available for ranking.")
# ==========================================================
# 16. FOOTER
# ==========================================================

st.divider()

st.caption(
    "SecureWatch | Mini SOC Security Monitoring System"
)

st.caption(
    "Automated Login Monitoring | PostgreSQL | Email Alerts"
)

# ==========================================================
# PERSISTENT SECURITY ALERT HISTORY
# ==========================================================

st.header("📚 Persistent Security Alert History")

try:
    history_connection = psycopg2.connect(
    st.secrets["DATABASE_URL"]
)

    history_query = """
    SELECT
        id,
        ip_address,
        failed_attempts,
        severity,
        created_at,
        email_sent
    FROM security_alert_history
    ORDER BY created_at DESC;
"""
    history_df = pd.read_sql_query(
        history_query,
        history_connection
    )

    history_connection.close()

    if not history_df.empty:
        st.dataframe(
            history_df,
            width="stretch"
        )
        st.success("Previous security alerts loaded successfully!")
    else:
        st.info("No previous security alerts found.")

except Exception as e:
    st.error("Could not load security alert history.")
    st.code(str(e))

# ==========================================================
# 1. IP INTELLIGENCE TEST
# ==========================================================

st.divider()
st.header("🔍 IP Intelligence Test")

test_ip = "192.168.1.10"

ip_type = classify_ip(test_ip)

st.write("IP Address:", test_ip)
st.write("IP Type:", ip_type)

if ip_type == "Private IP":
    st.info("This is a private network IP address.")
else:
    st.success("This is a public IP address.")


# ==========================================================
# 2. THREAT INTELLIGENCE
# ==========================================================

st.divider()
st.header("🛡️ Threat Intelligence")

st.write(
    "SecureWatch uses AbuseIPDB to check suspicious "
    "IP addresses and identify possible threats."
)

st.info(
    "You can manually check a public IP address "
    "in the section below."
)


# ==========================================================
# 3. MANUAL THREAT INTELLIGENCE
# ==========================================================

st.divider()
st.header("🔎 Manual Threat Intelligence")

manual_ip = st.text_input(
    "Enter an IP Address",
    placeholder="Example: 8.8.8.8",
    key="manual_threat_ip"
)

if st.button("Check IP Reputation", key="manual_ip_check"):

    if not manual_ip.strip():

        st.warning("Please enter an IP address.")

    else:

        with st.spinner("Checking IP reputation..."):

            reputation = check_ip_reputation(manual_ip.strip())

        if "error" in reputation:

            st.error(reputation["error"])

        else:

            score = reputation.get(
                "abuseConfidenceScore", 0
            )

            if score >= 75:
                threat_level = "HIGH"
            elif score >= 25:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            st.success("IP reputation check completed!")

            col1, col2, col3 = st.columns(3)

            col1.metric("Abuse Score", f"{score}%")

            col2.metric(
                "Total Reports",
                reputation.get("totalReports", 0)
            )

            col3.metric(
                "Threat Level",
                threat_level
            )

            st.write(
                "Country:",
                reputation.get("countryCode") or "Unknown"
            )

            st.write(
                "ISP:",
                reputation.get("isp") or "Unknown"
            )

            st.write(
                "Domain:",
                reputation.get("domain") or "Unknown"
            )
# ==========================================================
# SOC INCIDENT INVESTIGATION
# ==========================================================

st.divider()
st.header("🕵️ SOC Incident Investigation")

if st.button("Investigate IP Login History", key="investigate_ip"):

    if not manual_ip.strip():

        st.warning("Please enter an IP address first.")

    else:

        try:

            with psycopg2.connect(DATABASE_URL) as connection:

                investigation_df = pd.read_sql_query(
                    """
                    SELECT ip_address, status, login_time
                    FROM login_logs
                    WHERE ip_address = %s
                    ORDER BY login_time DESC;
                    """,
                    connection,
                    params=(manual_ip.strip(),)
                )

            if not investigation_df.empty:

                total_attempts = len(investigation_df)

                failed_attempts = (
                    investigation_df["status"]
                    .astype(str)
                    .str.lower() == "failed"
                ).sum()

                successful_attempts = (
                    investigation_df["status"]
                    .astype(str)
                    .str.lower() == "success"
                ).sum()

                col1, col2, col3 = st.columns(3)

                col1.metric("Total Attempts", total_attempts)
                col2.metric("Failed Attempts", int(failed_attempts))
                col3.metric("Successful Attempts", int(successful_attempts))

                st.subheader("IP Login History")

                st.dataframe(
                    investigation_df,
                    hide_index=True,
                    width="stretch"
                )

            else:

                st.info("No login history found for this IP.")

        except Exception as e:

            st.error("IP investigation failed.")
            st.code(str(e))
            # ==========================================================
# AUTOMATED SECURITY RECOMMENDATIONS
# ==========================================================

st.divider()
st.subheader("🛡️ Automated Security Recommendations")

if not ip_counts.empty:

    recommendations = {
        "CRITICAL": "Block IP immediately and investigate.",
        "HIGH": "Investigate IP and monitor activity.",
        "MEDIUM": "Monitor failed login attempts.",
        "LOW": "Continue normal security monitoring."
    }

    recommendation_df = ip_counts[
        ["IP Address", "Failed Attempts", "Risk Score", "Risk Level"]
    ].copy()

    recommendation_df["Recommended Action"] = (
        recommendation_df["Risk Level"].map(recommendations)
    )

    st.dataframe(
        recommendation_df,
        hide_index=True,
        width="stretch"
    )

else:

    st.info("No security recommendations available.")
    # ==========================================================
# SOC INCIDENT RESPONSE PLAYBOOK
# ==========================================================

st.divider()
st.subheader("📋 SOC Incident Response Playbook")

selected_priority = st.selectbox(
    "Select Incident Priority",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

response_steps = {
    "CRITICAL": [
        "Identify the suspicious IP address.",
        "Block the IP using firewall rules after verification.",
        "Check related login activities.",
        "Investigate possible account compromise.",
        "Record the incident for future analysis."
    ],

    "HIGH": [
        "Investigate the suspicious IP address.",
        "Review failed login attempts.",
        "Check IP reputation.",
        "Monitor further activity.",
        "Record investigation findings."
    ],

    "MEDIUM": [
        "Review login activity.",
        "Monitor repeated failed attempts.",
        "Check IP reputation.",
        "Record suspicious activity."
    ],

    "LOW": [
        "Continue normal monitoring.",
        "Review unusual login activity.",
        "Record important observations."
    ]
}

st.write("Recommended response steps:")

for step in response_steps[selected_priority]:
    st.write("☐", step)
    # ==========================================================
# SECURITY ANALYST INVESTIGATION NOTES
# ==========================================================

st.divider()
st.subheader("📝 Security Analyst Investigation Notes")

if not ip_counts.empty:

    selected_ip = st.selectbox(
        "Select IP Address",
        ip_counts["IP Address"].astype(str).unique()
    )

    analyst_notes = st.text_area(
        "Enter Investigation Notes",
        placeholder="Write your investigation observations here..."
    )

    if analyst_notes.strip():

        report_content = (
            f"SecureWatch Investigation Report\n"
            f"IP Address: {selected_ip}\n"
            f"Investigation Notes:\n{analyst_notes}\n"
        )

        st.download_button(
            label="Download Investigation Notes",
            data=report_content,
            file_name=f"Investigation_{selected_ip}.txt",
            mime="text/plain"
        )

    else:
        st.info("Enter investigation notes to download the report.")

else:

    st.info("No IP addresses available for investigation.")
    # ==========================================================
# CRITICAL THREAT ALERT NOTIFICATION
# ==========================================================

st.divider()
st.subheader("🚨 Critical Threat Alert Notification")

if not ip_counts.empty:

    critical_ips = ip_counts[
        ip_counts["Risk Level"] == "CRITICAL"
    ]

    if not critical_ips.empty:

        st.error(
            f"⚠️ {len(critical_ips)} CRITICAL threat(s) detected!"
        )

        st.dataframe(
            critical_ips[
                [
                    "IP Address",
                    "Failed Attempts",
                    "AbuseIPDB Score",
                    "Risk Score",
                    "Risk Level"
                ]
            ],
            hide_index=True,
            width="stretch"
        )

    else:

        st.success("No CRITICAL threats detected.")

else:

    st.info("No IP data available.")
    # ==========================================================
# SECURITY INCIDENT STATUS TRACKER
# ==========================================================

st.divider()
st.subheader("📌 Security Incident Status Tracker")

if not ip_counts.empty:

    incident_tracker = ip_counts[
        [
            "IP Address",
            "Failed Attempts",
            "Risk Score",
            "Risk Level"
        ]
    ].copy()

    incident_tracker["Incident Status"] = "OPEN"

    updated_tracker = st.data_editor(
        incident_tracker,
        hide_index=True,
        width="stretch",
        disabled=[
            "IP Address",
            "Failed Attempts",
            "Risk Score",
            "Risk Level"
        ],
        column_config={
            "Incident Status": st.column_config.SelectboxColumn(
                "Incident Status",
                options=[
                    "OPEN",
                    "INVESTIGATING",
                    "RESOLVED"
                ],
                required=True
            )
        }
    )

    st.download_button(
        "Download Incident Status Report",
        data=updated_tracker.to_csv(index=False),
        file_name="SecureWatch_Incident_Status.csv",
        mime="text/csv"
    )

else:

    st.info("No incidents available to track.")
    # ==========================================================
# RISK SCORE BREAKDOWN
# ==========================================================

st.divider()
st.subheader("🔍 Risk Score Breakdown")

if not ip_counts.empty:

    risk_breakdown = ip_counts[
        [
            "IP Address",
            "Failed Attempts",
            "AbuseIPDB Score",
            "Risk Score",
            "Risk Level"
        ]
    ].copy()

    risk_breakdown["Login Risk"] = (
        risk_breakdown["Failed Attempts"] * 5
    ).clip(upper=50)

    abuse_scores = pd.to_numeric(
        risk_breakdown["AbuseIPDB Score"],
        errors="coerce"
    ).fillna(0)

    risk_breakdown["Reputation Risk"] = abuse_scores * 0.5

    st.dataframe(
        risk_breakdown[
            [
                "IP Address",
                "Login Risk",
                "Reputation Risk",
                "Risk Score",
                "Risk Level"
            ]
        ],
        hide_index=True,
        width="stretch"
    )

    st.caption(
        "Risk Score = Login Risk + Reputation Risk (maximum 100)."
    )

else:

    st.info("No risk data available.")
    # ==========================================================
# SECURITY EVENT SEARCH
# ==========================================================

st.divider()
st.subheader("🔎 Security Event Search")

if not ip_counts.empty:

    search_ip = st.text_input(
        "Enter IP Address to Search"
    )

    if search_ip.strip():

        search_results = ip_counts[
            ip_counts["IP Address"]
            .astype(str)
            .str.contains(
                search_ip.strip(),
                case=False,
                na=False
            )
        ]

        if not search_results.empty:

            st.success(
                f"{len(search_results)} matching result(s) found."
            )

            st.dataframe(
                search_results,
                hide_index=True,
                width="stretch"
            )

        else:

            st.warning("No matching IP address found.")

else:

    st.info("No security events available.")
    # ==========================================================
# SECURITY STATISTICS SUMMARY
# ==========================================================

st.divider()
st.subheader("📈 Security Statistics Summary")

if not ip_counts.empty:

    total_suspicious_ips = len(ip_counts)

    total_critical = (
        ip_counts["Risk Level"] == "CRITICAL"
    ).sum()

    average_risk = round(
        ip_counts["Risk Score"].mean(), 2
    )

    highest_risk = ip_counts["Risk Score"].max()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Suspicious IPs",
        total_suspicious_ips
    )

    col2.metric(
        "Critical Incidents",
        total_critical
    )

    col3.metric(
        "Average Risk Score",
        average_risk
    )

    col4.metric(
        "Highest Risk Score",
        highest_risk
    )

else:

    st.info("No security statistics available.")
    # ==========================================================
# SECURITY SYSTEM HEALTH MONITOR
# ==========================================================

st.divider()
st.subheader("🖥️ Security System Health Monitor")

# PostgreSQL Status
try:

    with psycopg2.connect(
        st.secrets["DATABASE_URL"]
    ) as connection:

        st.success("🟢 PostgreSQL: Connected")

except Exception:

    st.error("🔴 PostgreSQL: Connection Failed")

# AbuseIPDB Status
if os.getenv("ABUSEIPDB_API_KEY") or st.secrets.get(
    "ABUSEIPDB_API_KEY"
):

    st.success("🟢 AbuseIPDB: API Key Configured")

else:

    st.warning("🟡 AbuseIPDB: API Key Missing")

# Email Status
email_address = os.getenv("EMAIL_ADDRESS") or st.secrets.get(
    "EMAIL_ADDRESS"
)

email_password = os.getenv("EMAIL_PASSWORD") or st.secrets.get(
    "EMAIL_PASSWORD"
)

if email_address and email_password:

    st.success("🟢 Email Alerts: Configured")

else:

    st.warning("🟡 Email Alerts: Not Configured")