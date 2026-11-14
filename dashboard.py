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

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD or not ALERT_EMAIL:
        return False, "Email settings are missing in .env."

    try:
        msg = EmailMessage()

        msg["Subject"] = f"SecureWatch - {severity} Security Alert"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ALERT_EMAIL

        msg.set_content(f"""
SECUREWATCH SECURITY ALERT

Suspicious login activity detected!

IP Address: {ip}
Failed Login Attempts: {attempts}
Severity: {severity}

Please investigate this activity.

SecureWatch - Mini SOC Security Monitoring System
""")

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

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
# SAVE SECURITY ALERTS INTO POSTGRESQL
# ==========================================================

try:
    history_connection = psycopg2.connect(
        dbname="securewatch_db",
        user="postgres",
        password=DB_PASSWORD,
        host="localhost",
        port="5432"
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
# 10. AUTOMATIC HIGH SEVERITY EMAIL ALERTS
# ==========================================================


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
                dbname="securewatch_db",
                user="postgres",
                password=DB_PASSWORD,
                host="localhost",
                port="5432"
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
                        dbname="securewatch_db",
                        user="postgres",
                        password=DB_PASSWORD,
                        host="localhost",
                        port="5432"
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

    st.dataframe(
        filtered_alerts,
        hide_index=True,
        width="stretch"
    )

    csv_data = filtered_alerts.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Security Report",
        data=csv_data,
        file_name="SecureWatch_Security_Report.csv",
        mime="text/csv"
    )

else:
    st.info("No security alerts available.")


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
        dbname="securewatch_db",
        user="postgres",
        password=DB_PASSWORD,
        host="localhost",
        port="5432"
    )

    history_query = """
        SELECT
            id,
            ip_address,
            failed_attempts,
            severity,
            detected_at,
            email_sent
        FROM security_alert_history
        ORDER BY detected_at DESC;
    """

    history_df = pd.read_sql_query(
        history_query,
        history_connection
    )

    history_connection.close()

    if not history_df.empty:
        st.dataframe(
            history_df,
            use_container_width=True
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
