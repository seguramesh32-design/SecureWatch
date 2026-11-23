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
# PROFESSIONAL SOC DASHBOARD STYLING
# ==========================================================

st.markdown("""
<style>

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

    for ip in ip_counts["IP Address"]:

        reputation = check_ip_reputation(str(ip))

        if "error" in reputation:

            st.warning(
                f"AbuseIPDB check failed for {ip}: {reputation['error']}"
            )

            reputation_scores.append("Unavailable")
            reputation_reports.append("Unavailable")
            reputation_levels.append("Unknown")

        else:

            score = int(reputation.get("abuseConfidenceScore", 0))
            reports = int(reputation.get("totalReports", 0))

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