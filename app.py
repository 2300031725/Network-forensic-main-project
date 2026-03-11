import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import sniffer

# Config
st.set_page_config(
    page_title="Visual Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Premium" Look
st.markdown("""
<style>
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    h1, h2, h3 {
        color: #f8fafc !important;
    }
    span[data-testid="stMetricValue"] {
        color: #38bdf8 !important; /* Sky Blue */
    }
    div[data-testid="stMetricDelta"] > svg {
        color: #4ade80 !important; /* Green */
    }
</style>
""", unsafe_allow_html=True)

# sidebar
st.sidebar.title("SecAnalytics")
page = st.sidebar.radio("Navigation", ["Dashboard Overview", "Traffic Analytics", "Forensics Logs", "About"])

# Start Sniffer
if 'sniffer_started' not in st.session_state:
    sniffer.start_sniffer()
    st.session_state['sniffer_started'] = True

# Main Content
if page == "Dashboard Overview":
    st.title("🛡️ Network Security Dashboard")
    st.markdown("### Real-time Traffic Monitoring")

    # Placeholder for live updates
    placeholder = st.empty()

    # Loop for real-time updates (simulated with rerun or autorefresh logic)
    # Streamlit refresh logic is handled by the script rerunning on interaction or user-triggered updates.
    # For auto-refresh, we can use a loop with st.empty() inside, but standard way implies user refresh or `st_autorefresh`.
    # Here we use a button or just refresh on interaction. For "Live" feel, let's use a loop in a dedicated container.
    
    if st.button('Start Live Monitoring'):
        while True:
            stats = sniffer.get_stats()
            df = sniffer.get_dataframe()

            with placeholder.container():
                # KPI Cards
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Packets", stats["total_packets"], "+12/s")
                col2.metric("Unique IPs", stats["unique_ips"], "Active")
                col3.metric("Threats Detected", len(stats["alerts"]), "Low")
                col4.metric("Protocol Types", len(stats["protocols"]), "TCP/UDP")

                # Charts Row 1
                chart_col1, chart_col2 = st.columns([2, 1])
                
                with chart_col1:
                    st.subheader("Traffic Volume (Packets over Time)")
                    if not df.empty:
                        # Resample for time series
                        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                        traffic_over_time = df.set_index('Timestamp').resample('1S').count()['Protocol']
                        fig_traffic = px.area(traffic_over_time, x=traffic_over_time.index, y='Protocol', labels={'Protocol': 'Packets', 'index': 'Time'})
                        fig_traffic.update_layout(paper_bgcolor="#1e293b", plot_bgcolor="#1e293b", font_color="#f8fafc")
                        st.plotly_chart(fig_traffic, use_container_width=True)
                    else:
                        st.info("Waiting for packets...")

                with chart_col2:
                    st.subheader("Protocol Distribution")
                    fig_pie = px.pie(names=stats["protocols"].keys(), values=stats["protocols"].values(), hole=0.4)
                    fig_pie.update_layout(paper_bgcolor="#1e293b", plot_bgcolor="#1e293b", font_color="#f8fafc", showlegend=False)
                    st.plotly_chart(fig_pie, use_container_width=True)

                # Recent Alerts
                st.subheader("Recent Security Alerts")
                if stats["alerts"]:
                    st.dataframe(pd.DataFrame(stats["alerts"]), hide_index=True)
                else:
                    st.success("No active threats detected.")

            time.sleep(1) # Refresh every second

    else:
        st.info("Click 'Start Live Monitoring' to view real-time data.")
        stats = sniffer.get_stats()

        # Static View (Latest Snapshot)
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Packets", stats["total_packets"])
        col2.metric("Unique IPs", stats["unique_ips"])
        col3.metric("Threats Detected", len(stats["alerts"]))
        col4.metric("Protocol Types", len(stats["protocols"]))

elif page == "Forensics Logs":
    st.title("📂 Forensic Investigation")
    df = sniffer.get_dataframe()
    if not df.empty:
        search_term = st.text_input("Search Logs (IP, Protocol)")
        if search_term:
            df = df[df.astype(str).apply(lambda row: row.str.contains(search_term, case=False).any(), axis=1)]
        st.dataframe(df, use_container_width=True, height=600)
    else:
        st.info("No packets captured yet. Start monitoring in Dashboard.")

elif page == "About":
    st.title("ℹ️ About")
    st.write("Visual Security Analytics v1.0")
    st.write("Built with Streamlit & Scapy")
