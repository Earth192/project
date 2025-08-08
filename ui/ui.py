import streamlit as st
import pandas as pd
import json
import os
import time
import requests
from datetime import datetime
from functools import lru_cache

st.set_page_config(page_title="Firewall IDS Dashboard", layout="wide")
st.title("🚨 Intrusion Detection System Dashboard")

LOG_DIR = "/Users/jenish/Documents/IDS/"
JSON_LOG_FILE = os.path.join(LOG_DIR, "firewall_logs.json")

# Geolocation 
@lru_cache(maxsize=1000)
def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=0)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "")
            region = data.get("region", "")
            country = data.get("country", "")
            return f"🌍 {city}, {region}, {country}".strip(", ")
        else:
            return "🌐 Unknown"
    except Exception:
        return "🌐 Unknown"

@st.cache_data(ttl=5)  # Cache logs for 5 seconds
def load_logs(path=JSON_LOG_FILE):
    all_logs = []

    if not os.path.exists(path):
        return pd.DataFrame()

    with open(path, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line.strip())
                log_entry['is_threat'] = "BLOCK" in log_entry.get("action", "")
                log_entry['src_geo'] = get_geolocation(log_entry.get("src_ip", ""))
                log_entry['dst_geo'] = get_geolocation(log_entry.get("dst_ip", ""))
                all_logs.append(log_entry)
            except json.JSONDecodeError:
                continue

    return pd.DataFrame(all_logs)

# Sidebar
st.sidebar.header("🔍 Filters")
ip_filter = st.sidebar.text_input("Search IP", key="ip_filter")
auto_refresh = st.sidebar.checkbox("🔄 Real-time Monitoring", value=True, key="auto_refresh")
refresh_interval = st.sidebar.slider("⏱️ Refresh Interval (sec)", 1, 10, 5, key="refresh_interval")

# Load logs
df = load_logs()

if df.empty:
    st.warning("⚠️ No logs loaded. Please run the IDS system.")
    st.stop()

# Filters
filtered_df = df.copy()

if ip_filter:
    filtered_df = filtered_df[
        filtered_df['src_ip'].str.contains(ip_filter, na=False) |
        filtered_df['dst_ip'].str.contains(ip_filter, na=False)
    ]

if 'protocol' in df.columns:
    protocol_filter = st.sidebar.selectbox("Protocol", ["All"] + sorted(df['protocol'].dropna().unique()), key="protocol_filter")
    if protocol_filter != "All":
        filtered_df = filtered_df[filtered_df['protocol'] == protocol_filter]

action_filter = st.sidebar.selectbox("Action", ["All", "ALLOW", "BLOCK"], key="action_filter")
if action_filter != "All":
    filtered_df = filtered_df[filtered_df['action'] == action_filter]

# Log table with red-row threat highlighting
def highlight_threat(row):
    return ['background-color: red; color: white' if row.get('is_threat') else '' for _ in row]

st.subheader("📋 Log Entries (Newest First)")
st.dataframe(filtered_df.sort_values("timestamp", ascending=False).style.apply(highlight_threat, axis=1), use_container_width=True)

# Charts
st.subheader("📊 Summary")
st.bar_chart(filtered_df['action'].value_counts())
if 'protocol' in filtered_df.columns:
    st.bar_chart(filtered_df['protocol'].value_counts())

# Auto-refresh logic
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
