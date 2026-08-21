import streamlit as st
import pandas as pd

from aegis_lite.log_parser import read_log_file
from aegis_lite.statistics import generate_security_summary
from aegis_lite.threat_analysis import get_detected_threats
from aegis_lite.geo_ip import get_ip_location

st.set_page_config(
    page_title="Aegis-Lite",
    page_icon="🛰️",
    layout="wide",
)

st.title("🛰️ Aegis-Lite Security Dashboard")
st.write("Security log monitoring and threat analysis system.")

access_logs = read_log_file("sample_logs/access.log")
attack_logs = read_log_file("sample_logs/attack.log")

summary = generate_security_summary(
    access_logs,
    attack_logs,
)

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Access Logs",
        summary["total_access_logs"]
    )

with col2:
    st.metric(
        "Attack Logs",
        summary["total_attack_logs"]
    )

with col3:
    st.metric(
        "Detected Threats",
        summary["total_threats"]
    )

st.subheader("Threat Analysis")

detected_threats = get_detected_threats(attack_logs)

threat_df = pd.DataFrame(detected_threats)

threat_options = ["All"] + sorted(
    threat_df["Threat Type"].unique().tolist()
)

selected_threat = st.selectbox(
    "Filter by Threat Type",
    threat_options
)

if selected_threat != "All":
    threat_df = threat_df[
        threat_df["Threat Type"] == selected_threat
    ]

severity_options = ["All"] + sorted(
    threat_df["Severity"].unique().tolist()
)

selected_severity = st.selectbox(
    "Filter by Severity",
    severity_options
)

if selected_severity != "All":
    threat_df = threat_df[
        threat_df["Severity"] == selected_severity
    ]

st.dataframe(
    threat_df,
    width="stretch"
)

st.subheader("SOC Attack Map")

DEMO_PUBLIC_IPS = [
    {
        "ip": "8.8.8.8",
        "Threat Type": "SQL Injection",
        "Severity": "High",
        "Risk Score": 70,
    },
    {
        "ip": "1.1.1.1",
        "Threat Type": "Cross-Site Scripting (XSS)",
        "Severity": "High",
        "Risk Score": 70,
    },
]
map_rows = []
unmapped_rows = []

for threat in detected_threats:
    ip = threat["IP Address"]

    location = get_ip_location(ip)

    latitude = location.get("latitude")
    longitude = location.get("longitude")
    country = location.get("country")
    city = location.get("city")

    if latitude is not None and longitude is not None:
        map_rows.append({
            "lat": latitude,
            "lon": longitude,
            "IP Address": ip,
            "Threat Type": threat["Threat Type"],
            "Severity": threat["Severity"],
            "Risk Score": threat["Risk Score"],
            "Country": country,
            "City": city,
        })
    else:
        unmapped_rows.append({
            "IP Address": ip,
            "Threat Type": threat["Threat Type"],
            "Severity": threat["Severity"],
            "Risk Score": threat["Risk Score"],
            "Country": country,
            "City": city,
        })

for demo in DEMO_PUBLIC_IPS:
    location = get_ip_location(demo["ip"])

    latitude = location.get("latitude")
    longitude = location.get("longitude")
    country = location.get("country")
    city = location.get("city")

    if latitude is not None and longitude is not None:
        map_rows.append({
            "lat": latitude,
            "lon": longitude,
            "IP Address": demo["ip"],
            "Threat Type": demo["Threat Type"],
            "Severity": demo["Severity"],
            "Risk Score": demo["Risk Score"],
            "Country": country,
            "City": city,
        })

map_df = pd.DataFrame(map_rows)

if not map_df.empty:
    st.map(
        map_df,
        latitude="lat",
        longitude="lon",
    )
else:
    st.info(
        "No mappable public IP addresses were found."
    )

st.caption(
    "Map visualization includes public demo IP addresses because "
    "the sample attack dataset uses reserved documentation IP ranges."
)

if unmapped_rows:
    st.write("Unmapped / Reserved IP Addresses")

    unmapped_df = pd.DataFrame(unmapped_rows)

    st.dataframe(
        unmapped_df,
        width="stretch",
    )

st.subheader("Threat Distribution")

threat_count_df = pd.DataFrame(
    list(summary["threat_counts"].items()),
    columns=["Threat Type", "Count"],
)

st.bar_chart(
    threat_count_df,
    x="Threat Type",
    y="Count",
)

st.subheader("HTTP Status Code Distribution")

col1, col2 = st.columns(2)

access_status_df = pd.DataFrame(
    list(summary["access_status_codes"].items()),
    columns=["Status Code", "Count"],
)

attack_status_df = pd.DataFrame(
    list(summary["attack_status_codes"].items()),
    columns=["Status Code", "Count"],
)

with col1:
    st.write("Access Logs")
    st.bar_chart(
        access_status_df,
        x="Status Code",
        y="Count",
    )

with col2:
    st.write("Attack Logs")
    st.bar_chart(
        attack_status_df,
        x="Status Code",
        y="Count",
    )

st.subheader("Top IP Addresses")

ip_df = pd.DataFrame(
    list(summary["top_ip_addresses"].items()),
    columns=["IP Address", "Request Count"],
)

ip_df = ip_df.sort_values(
    by="Request Count",
    ascending=False,
)

st.bar_chart(
    ip_df,
    x="IP Address",
    y="Request Count",
)

st.subheader("Log Viewer")

log_type = st.selectbox(
    "Select Log Type",
    ["Access Logs", "Attack Logs"]
)

if log_type == "Access Logs":
    selected_logs = access_logs
else:
    selected_logs = attack_logs

logs_df = pd.DataFrame(selected_logs)

status_options = ["All"] + sorted(
    logs_df["status_code"].unique().tolist()
)

selected_status = st.selectbox(
    "Filter by Status Code",
    status_options
)

if selected_status != "All":
    logs_df = logs_df[
        logs_df["status_code"] == selected_status
    ]

ip_options = ["All"] + sorted(
    logs_df["ip"].dropna().unique().tolist()
)

selected_ip = st.selectbox(
    "Filter by IP Address",
    ip_options
)

if selected_ip != "All":
    logs_df = logs_df[
        logs_df["ip"] == selected_ip
    ]

st.dataframe(
    logs_df,
    width="stretch"
)