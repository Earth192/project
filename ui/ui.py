import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="Firewall IDS Dashboard", layout="wide")
st.title("🚨 Intrusion Detection System Dashboard")

# Load logs
def load_logs(path="/Users/jenish/Documents/IDS/"):
    all_logs = []

    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isfile(file_path) and filename.endswith('.json'):
            with open(file_path, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        all_logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue  # skip malformed lines

    return pd.DataFrame(all_logs)

df = load_logs()

# Filters
st.sidebar.header("Filters")
ip_filter = st.sidebar.text_input("Search IP")

# Use unique keys for each selectbox
protocol_filter = st.sidebar.selectbox("Protocol", ["All"] + sorted(df['protocol'].unique().tolist()), key="protocol_filter_1")
action_filter = st.sidebar.selectbox("Action", ["All", "ALLOW", "BLOCK"], key="action_filter")

filtered_df = df.copy()
if ip_filter:
    filtered_df = filtered_df[filtered_df['src_ip'].str.contains(ip_filter) | filtered_df['dst_ip'].str.contains(ip_filter)]
if protocol_filter != "All":
    filtered_df = filtered_df[filtered_df['protocol'] == protocol_filter]
if action_filter != "All":
    filtered_df = filtered_df[filtered_df['action'] == action_filter]

# Only reload logs once — removed second df = load_logs()
if df.empty:
    st.warning("No logs loaded. Please run the IDS first to generate logs.")
else:
    # Avoid duplicate filtering again; just show info or handle fallback
    if 'protocol' not in df.columns:
        st.sidebar.warning("⚠️ 'protocol' field not found in logs. Protocol filtering disabled.")

st.subheader("📋 Log Entries")
st.dataframe(filtered_df.sort_values("timestamp", ascending=False))

st.subheader("📊 Summary")
st.bar_chart(filtered_df['action'].value_counts())
st.bar_chart(filtered_df['protocol'].value_counts())


# df = pd.read_json("/Users/jenish/Documents/IDS/firewall_logs.json", lines=True)
