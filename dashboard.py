import streamlit as st
import pandas as pd

from aegis_lite.log_parser import read_log_file
from aegis_lite.statistics import generate_security_summary
from aegis_lite.threat_analysis import get_detected_threats

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

st.subheader("Threat Distribution")

threat_df = pd.DataFrame(
    list(summary["threat_counts"].items()),
    columns=["Threat Type", "Count"],
)

st.bar_chart(
    threat_df,
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

st.dataframe(
    threat_df,
    width="stretch"
)