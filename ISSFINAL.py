
import streamlit as st
import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
import random
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import plotly.express as px
import plotly.graph_objects as go


st.set_page_config(page_title="AI-SOC Log Dashboard", layout="wide")
st.title("AI-Driven Security Operations Center Dashboard")


def generate_logs(num_entries=100):
    event_types = ['login_failed', 'port_scan', 'malware_detected', 'normal_activity', 'suspicious_traffic']
    messages = {
        'login_failed': 'User login attempt failed.',
        'port_scan': 'Port scan activity detected.',
        'malware_detected': 'Malware signature found.',
        'normal_activity': 'Normal traffic behavior.',
        'suspicious_traffic': 'Suspicious pattern detected.'
    }
    ip_pool = [f"192.168.1.{i}" for i in range(1, 50)]
    users = ['admin', 'user1', 'user2', 'service_account', 'guest']
    
    logs = []
    base_time = datetime.now()
    
    for _ in range(num_entries):
        event = random.choice(event_types)
        log_time = base_time - timedelta(seconds=random.randint(0, 3600))
        
        log_entry = {
            "timestamp": log_time.isoformat(),
            "src_ip": random.choice(ip_pool),
            "event_type": event,
            "rule_level": {
                'login_failed': random.randint(3, 5),
                'port_scan': random.randint(5, 7),
                'malware_detected': random.randint(7, 10),
                'normal_activity': random.randint(1, 3),
                'suspicious_traffic': random.randint(4, 8)
            }[event],
            "message": messages[event],
            "user": random.choice(users)
        }
        
        
        if random.random() < 0.1:
            log_entry["rule_level"] = random.randint(7, 10)
            log_entry["event_type"] = random.choice(['port_scan', 'malware_detected', 'suspicious_traffic'])
            log_entry["message"] = "Suspicious activity detected!"
        
        logs.append(log_entry)
    
    return logs

def save_logs_to_json(logs, filename="generated_logs.json"):
    with open(filename, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")
    return filename


st.sidebar.header("Options")
option = st.sidebar.radio("Choose data source:", 
                         ["Generate synthetic logs", "Upload log file"])

if option == "Generate synthetic logs":
    num_logs = st.sidebar.slider("Number of logs to generate", 100, 10000, 500)
    if st.sidebar.button("Generate Logs"):
        logs = generate_logs(num_logs)
        log_file = save_logs_to_json(logs)
        
        st.session_state.logs = logs
        st.session_state.log_file = log_file
        
        st.success(f"Generated {num_logs} log entries!")
        st.download_button(
            label="Download Generated Logs",
            data=open(log_file, 'rb').read(),
            file_name="generated_logs.json",
            mime="application/json"
        )
        
        
        st.subheader("Sample Generated Logs")
        st.json(logs[:5])
        
        
        df_logs = pd.DataFrame(logs)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
        
        
        le = LabelEncoder()
        df_logs['src_ip_encoded'] = le.fit_transform(df_logs['src_ip'])
        df_logs['user_encoded'] = le.fit_transform(df_logs['user'])
        
        features = df_logs[['rule_level', 'src_ip_encoded', 'user_encoded']]
        clf = IsolationForest(contamination=0.1)
        clf.fit(features)
        preds = clf.predict(features)
        df_logs['anomaly'] = np.where(preds == -1, 1, 0)
        
        
        total_logs = len(df_logs)
        anomaly_count = df_logs['anomaly'].sum()
        unique_ips = df_logs['src_ip'].nunique()
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Logs", total_logs)
        col2.metric("Anomalies Detected", anomaly_count)
        col3.metric("Unique Source IPs", unique_ips)
        
        
        st.markdown("## Log Preview")
        st.dataframe(df_logs[['timestamp', 'src_ip', 'event_type', 'rule_level', 'anomaly']].head(50), 
                    use_container_width=True)
        
        
        st.markdown("## Rule Level Distribution")
        fig1 = px.histogram(df_logs, x='rule_level', nbins=10,
                           title='Distribution of Rule Levels',
                           color='anomaly',
                           color_discrete_map={0: 'blue', 1: 'red'})
        st.plotly_chart(fig1, use_container_width=True)
        
        st.markdown("## Top Source IPs (Anomalies Only)")
        top_ips = df_logs[df_logs['anomaly'] == 1]['src_ip'].value_counts().nlargest(10).reset_index()
        top_ips.columns = ['src_ip', 'count']
        fig2 = px.bar(top_ips, x='src_ip', y='count',
                     title="Top IPs with Anomalies",
                     text='count',
                     color='count',
                     color_continuous_scale='reds')
        st.plotly_chart(fig2, use_container_width=True)
        
        st.markdown("## Anomalies Over Time")
        time_anomalies = df_logs[df_logs['anomaly'] == 1].groupby(
            df_logs['timestamp'].dt.floor('min')).size().reset_index(name='count')
        fig3 = go.Figure(data=go.Scatter(
            x=time_anomalies['timestamp'],
            y=time_anomalies['count'],
            mode='lines+markers',
            line=dict(color='red', width=2)))
        fig3.update_layout(title="Anomaly Count Over Time",
                          xaxis_title="Time",
                          yaxis_title="Count")
        st.plotly_chart(fig3, use_container_width=True)
        
        st.markdown("## Detailed Anomaly Logs")
        st.dataframe(df_logs[df_logs['anomaly'] == 1][['timestamp', 'src_ip', 'event_type', 'rule_level', 'message']], 
                    use_container_width=True)

elif option == "Upload log file":
    uploaded_file = st.sidebar.file_uploader("Upload a log file (JSON)", type=["json"])
    
    if uploaded_file:
        logs_json = uploaded_file.read().decode("utf-8")
        logs = [json.loads(line) for line in logs_json.strip().split("\n")]
        
        df = pd.DataFrame(logs)
        st.subheader("Uploaded Log Data")
        st.write(df.head())
        
        
        if 'rule' in df.columns and isinstance(df['rule'].iloc[0], dict):
            df['rule_level'] = df['rule'].apply(lambda x: x.get('level', 0))
        if 'data' in df.columns and isinstance(df['data'].iloc[0], dict):
            df['src_ip'] = df['data'].apply(lambda x: x.get('srcip', '0.0.0.0'))
        
        
        le = LabelEncoder()
        categorical_cols = [col for col in df.columns if df[col].dtype == 'object']
        for col in categorical_cols:
            try:
                df[col + '_encoded'] = le.fit_transform(df[col].astype(str))
            except:
                pass
        
        
        numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
        features = df[numeric_cols].fillna(0)
        
        if st.sidebar.button("Analyze Logs"):
            with st.spinner("Detecting anomalies..."):
                clf = IsolationForest(contamination=0.1)
                clf.fit(features)
                preds = clf.predict(features)
                df['anomaly'] = np.where(preds == -1, 1, 0)
                
                
                total_logs = len(df)
                anomaly_count = df['anomaly'].sum()
                unique_ips = df.get('src_ip', pd.Series([0])).nunique()
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Logs", total_logs)
                col2.metric("Anomalies Detected", anomaly_count)
                if 'src_ip' in df.columns:
                    col3.metric("Unique Source IPs", unique_ips)
                
                st.success(f"Detected {anomaly_count} anomalies out of {total_logs} logs")
                
                
                st.markdown("## Detailed Anomaly Logs")
                st.dataframe(df[df['anomaly'] == 1][['timestamp', 'src_ip', 'rule_level', 'anomaly']], 
                            use_container_width=True)
                
                
                if 'timestamp' in df.columns and 'rule_level' in df.columns:
                    st.markdown("##  Rule Level Distribution")
                    fig1 = px.histogram(df, x='rule_level', nbins=10,
                                      title='Distribution of Rule Levels',
                                      color='anomaly',
                                      color_discrete_map={0: 'blue', 1: 'red'})
                    st.plotly_chart(fig1, use_container_width=True)
                    
                    if 'src_ip' in df.columns:
                        st.markdown("## Top Source IPs (Anomalies Only)")
                        top_ips = df[df['anomaly'] == 1]['src_ip'].value_counts().nlargest(10).reset_index()
                        top_ips.columns = ['src_ip', 'count']
                        fig2 = px.bar(top_ips, x='src_ip', y='count',
                                     title="Top IPs with Anomalies",
                                     text='count',
                                     color='count',
                                     color_continuous_scale='reds')
                        st.plotly_chart(fig2, use_container_width=True)
                    
                    st.markdown("## Anomalies Over Time")
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    time_anomalies = df[df['anomaly'] == 1].groupby(
                        df['timestamp'].dt.floor('min')).size().reset_index(name='count')
                    fig3 = go.Figure(data=go.Scatter(
                        x=time_anomalies['timestamp'],
                        y=time_anomalies['count'],
                        mode='lines+markers',
                        line=dict(color='red', width=2)))
                    fig3.update_layout(title="Anomaly Count Over Time",
                                    xaxis_title="Time",
                                    yaxis_title="Count")
                    st.plotly_chart(fig3, use_container_width=True)