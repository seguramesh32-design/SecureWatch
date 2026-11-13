
# ==========================================================
# SECUREWATCH - MINI SOC SECURITY MONITORING SYSTEM
# ==========================================================

import csv
import os
import psycopg2
from datetime import datetime
from getpass import getpass

print("=" * 55)
print("          WELCOME TO SECUREWATCH")
print("       MINI SOC SECURITY MONITORING SYSTEM")
print("=" * 55)

# STEP 1: PROJECT FILE PATHS

folder = os.path.dirname(os.path.abspath(__file__))

csv_path = os.path.join(folder, "login_logs.csv")
alert_path = os.path.join(folder, "security_alerts.txt")
report_path = os.path.join(folder, "postgresql_report.txt")

# STEP 2: INITIALIZE COUNTERS

login_counts = {}
suspicious_ips = []
security_alerts = []

total_logins = 0
failed_logins = 0
successful_logins = 0

# STEP 3: CHECK CSV FILE

if not os.path.exists(csv_path):
    print("ERROR: login_logs.csv file not found!")
    raise SystemExit

# STEP 4: READ CSV LOGIN RECORDS

try:
    with open(csv_path, "r", newline="", encoding="utf-8-sig") as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file has no headings.")

        reader.fieldnames = [name.strip() for name in reader.fieldnames]

        if not {"ip_address", "status"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain ip_address and status columns.")

        for row in reader:

            ip = (row.get("ip_address") or "").strip()
            status = (row.get("status") or "").strip().lower()

            if not ip or status not in ("failed", "success"):
                print("Skipping invalid login record.")
                continue

            total_logins += 1

            if status == "failed":
                failed_logins += 1
                login_counts[ip] = login_counts.get(ip, 0) + 1

            elif status == "success":
                successful_logins += 1

except (OSError, ValueError, csv.Error) as error:
    print("CSV ERROR:", error)
    raise SystemExit

# STEP 5: DETECT SUSPICIOUS IP ADDRESSES
print("Total detected alerts:",len(security_alerts))

for ip, count in login_counts.items():

    if count >= 3:

        suspicious_ips.append(ip)

        if count >= 5:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        alert = {
            "ip_address": ip,
            "failed_attempts": count,
            "severity": severity,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        security_alerts.append(alert)

# STEP 6: POSTGRESQL DATABASE CONNECTION

print("\nConnecting to PostgreSQL...")

connection = None
cur = None

try:
    db_password = getpass("Enter PostgreSQL password: ")

    connection = psycopg2.connect(
        host="localhost",
        database="securewatch_db",
        user="postgres",
        password=db_password,
        port="5432"
    )

    cur = connection.cursor()

    print("PostgreSQL connected successfully!")

    # Create login_logs table if it does not exist

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(50),
            status VARCHAR(20),
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Create security_alerts table if it does not exist

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(50),
            failed_attempts INTEGER,
            severity VARCHAR(20),
            alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # STEP 7: STORE LOGIN RECORDS IN POSTGRESQL

    with open(csv_path, "r", newline="", encoding="utf-8-sig") as file:

        reader = csv.DictReader(file)

        for row in reader:

            ip = (row.get("ip_address") or "").strip()
            status = (row.get("status") or "").strip().lower()

            if ip and status in ("failed", "success"):

                cur.execute(
                    """
                    INSERT INTO login_logs
                    (ip_address, status)
                    VALUES (%s, %s)
                    """,
                    (ip, status)
                )

    # STEP 8: SAVE SECURITY ALERTS IN POSTGRESQL

    for alert in security_alerts:

        cur.execute(
            """
            INSERT INTO security_alerts
            (ip_address, failed_attempts, severity)
            VALUES (%s, %s, %s)
            """,
            (
                alert["ip_address"],
                alert["failed_attempts"],
                alert["severity"]
            )
        )

    connection.commit()

    print("\nLogin records saved successfully!")
    print("Security alerts saved in PostgreSQL!")

    # STEP 9: GET DATABASE COUNTS

    cur.execute("SELECT COUNT(*) FROM login_logs")
    database_total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM security_alerts")
    database_alert_total = cur.fetchone()[0]

    # STEP 10: SAVE POSTGRESQL REPORT

    with open(report_path, "w", encoding="utf-8") as file:

        file.write("SECUREWATCH POSTGRESQL SECURITY REPORT\n")
        file.write("=" * 45 + "\n")
        file.write(f"Total Logins in CSV: {total_logins}\n")
        file.write(f"Failed Logins in CSV: {failed_logins}\n")
        file.write(f"Successful Logins in CSV: {successful_logins}\n")
        file.write(f"Total Database Login Records: {database_total}\n")
        file.write(f"Total Database Security Alerts: {database_alert_total}\n")

    print("\nPostgreSQL report saved successfully!")

except (psycopg2.Error, OSError, csv.Error) as error:

    print("ERROR:", error)

    if connection:
        connection.rollback()

    raise SystemExit

finally:

    if cur:
        cur.close()

    if connection:
        connection.close()

# STEP 11: DISPLAY SECURITY SUMMARY

print("\n" + "=" * 45)
print("          SECURITY SUMMARY")
print("=" * 45)

print("Total Logins:", total_logins)
print("Failed Logins:", failed_logins)
print("Successful Logins:", successful_logins)

# STEP 12: DISPLAY SUSPICIOUS IP ADDRESSES

print("\nSUSPICIOUS IP ADDRESSES")
print("-" * 45)

if suspicious_ips:

    for ip in suspicious_ips:
        print(ip, "- Suspicious Activity Detected")

else:
    print("No suspicious IP addresses found.")

# STEP 13: DISPLAY SECURITY ALERTS

print("\nSECURITY ALERTS")
print("-" * 45)

if security_alerts:

    for alert in security_alerts:

        print("IP Address:", alert["ip_address"])
        print("Failed Attempts:", alert["failed_attempts"])
        print("Severity:", alert["severity"])
        print("Time:", alert["time"])
        print("-" * 30)

else:
    print("No security alerts.")

# STEP 14: SAVE SECURITY ALERT HISTORY TO TEXT FILE

with open(alert_path, "w", encoding="utf-8") as file:

    file.write("SECUREWATCH SECURITY ALERT HISTORY\n")
    file.write("=" * 45 + "\n")

    if security_alerts:

        for alert in security_alerts:

            file.write(f"IP Address: {alert['ip_address']}\n")
            file.write(f"Failed Attempts: {alert['failed_attempts']}\n")
            file.write(f"Severity: {alert['severity']}\n")
            file.write(f"Time: {alert['time']}\n")
            file.write("-" * 35 + "\n")

    else:
        file.write("No suspicious activity detected.\n")

print("\nSecurity alert history saved successfully!")

# STEP 15: FINAL MESSAGE

print("\n" + "=" * 55)
print("       SECUREWATCH SCAN COMPLETED!")
print("=" * 55)

print("PostgreSQL Report:", report_path)
print("Security Alerts:", alert_path)
