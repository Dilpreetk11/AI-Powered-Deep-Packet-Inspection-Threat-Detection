import streamlit as st
import pandas as pd
import json
import os
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="AI DPI Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Mode & Premium Cards)
st.markdown("""
<style>
    .main { background-color: #0E1117; }
    .stMetric {
        background-color: #1E222D;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #2E3440;
    }
    .metric-card {
        background: linear-gradient(135deg, #1E222D 0%, #252A37 100%);
        border: 1px solid #3B4252;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .threat-critical { color: #FF4D4D; font-weight: bold; }
    .threat-high { color: #FFA500; font-weight: bold; }
    .threat-medium { color: #F0E68C; font-weight: bold; }
    .threat-low { color: #4CAF50; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI-Powered Deep Packet Inspection & Threat Detection")
st.caption("Real-Time Network Flow Traffic Analysis, Machine Learning Classification & Explainable AI Risk Matrix")

# Load Reports
REPORT_JSON = "reports/dpi_report.json"
REPORT_CSV = "reports/dpi_report.csv"

if not os.path.exists(REPORT_JSON) or not os.path.exists(REPORT_CSV):
    st.warning("⚠️ No DPI Report found in `reports/`. Please run `python run_dpi.py <input.pcap> <output.pcap>` first to generate threat intelligence data.")
    st.info("Quick run command: `python run_dpi.py test_attack.pcap output.pcap`")
    st.stop()

with open(REPORT_JSON, 'r') as f:
    report_data = json.load(f)

summary = report_data.get('summary', {})
app_breakdown = report_data.get('app_breakdown', {})
df_flows = pd.DataFrame(report_data.get('flows', []))

# Sidebar Filters
st.sidebar.header("🔍 Flow Filters & Settings")

threat_levels = ["ALL"] + sorted(list(df_flows['threat_level'].unique())) if not df_flows.empty else ["ALL"]
selected_threat_level = st.sidebar.selectbox("Threat Level", threat_levels)

decisions = ["ALL"] + sorted(list(df_flows['decision'].unique())) if not df_flows.empty else ["ALL"]
selected_decision = st.sidebar.selectbox("Enforcement Decision", decisions)

apps = ["ALL"] + sorted(list(df_flows['application'].unique())) if not df_flows.empty else ["ALL"]
selected_app = st.sidebar.selectbox("Application", apps)

search_query = st.sidebar.text_input("Search IP / Domain / Reason", "")

# Apply Filters
df_filtered = df_flows.copy()
if not df_filtered.empty:
    if selected_threat_level != "ALL":
        df_filtered = df_filtered[df_filtered['threat_level'] == selected_threat_level]
    if selected_decision != "ALL":
        df_filtered = df_filtered[df_filtered['decision'] == selected_decision]
    if selected_app != "ALL":
        df_filtered = df_filtered[df_filtered['application'] == selected_app]
    if search_query:
        query_lower = search_query.lower()
        df_filtered = df_filtered[
            df_filtered['src_ip'].str.contains(query_lower, case=False) |
            df_filtered['dst_ip'].str.contains(query_lower, case=False) |
            df_filtered['rationale'].str.contains(query_lower, case=False)
        ]

# 1. Executive Top Metrics (KPIs)
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
m2.metric("Active Flows", f"{summary.get('active_flows', 0):,}")
m3.metric("Evaluated Flows", f"{summary.get('evaluated_flows', 0):,}")
m4.metric("High Threats", f"{summary.get('high_threats', 0):,}")
m5.metric("Avg Threat Score", f"{summary.get('avg_threat_score', 0):.1f}/100")
m6.metric("Inference Time", f"{summary.get('inference_time_ms', 0):.2f} ms")

st.markdown("---")

# 2. Charts Row 1
c1, c2 = st.columns([1, 1])

with c1:
    st.subheader("📊 Application Traffic Distribution")
    if app_breakdown:
        df_app = pd.DataFrame(list(app_breakdown.items()), columns=["Application", "Packets"])
        df_app = df_app.sort_values(by="Packets", ascending=False)
        st.bar_chart(df_app.set_index("Application"))
    else:
        st.info("No application data available.")

with c2:
    st.subheader("⚠️ Threat Score Distribution")
    if not df_flows.empty:
        fig, ax = plt.subplots(figsize=(6, 3.5))
        fig.patch.set_facecolor('#0E1117')
        ax.set_facecolor('#1E222D')
        
        n, bins, patches = ax.hist(df_flows['threat_score'], bins=10, color='#3B82F6', edgecolor='#1E222D')
        for i, p in enumerate(patches):
            if bins[i] >= 70: p.set_facecolor('#EF4444')
            elif bins[i] >= 40: p.set_facecolor('#F59E0B')
            else: p.set_facecolor('#10B981')
            
        ax.set_xlabel('Threat Score (0 - 100)', color='#D8DEE9')
        ax.set_ylabel('Number of Flows', color='#D8DEE9')
        ax.tick_params(colors='#D8DEE9')
        ax.spines['bottom'].set_color('#4C566A')
        ax.spines['left'].set_color('#4C566A')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        st.pyplot(fig)

st.markdown("---")

# 3. Threat Matrix & Explainable AI Table
st.subheader("🕵️ AI Flow Risk Matrix & Explainable AI (XAI) Drivers")

if not df_filtered.empty:
    st.dataframe(
        df_filtered[[
            "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", 
            "application", "threat_score", "threat_level", "confidence",
            "anomaly_score", "attack_type", "decision", "rationale"
        ]],
        use_container_width=True
    )
    
    st.markdown("### 🔎 Flow Detail Inspector & Feature Drivers")
    selected_flow_id = st.selectbox("Select Flow ID to Inspect", df_filtered['flow_id'].unique())
    selected_row = df_filtered[df_filtered['flow_id'] == selected_flow_id].iloc[0]
    
    col_a, col_b = st.columns([1, 1])
    with col_a:
        st.markdown(f"**Flow ID**: `{selected_row['flow_id']}`")
        st.markdown(f"**5-Tuple**: `{selected_row['src_ip']}:{selected_row['src_port']} ➔ {selected_row['dst_ip']}:{selected_row['dst_port']}` (Proto {selected_row['protocol']})")
        st.markdown(f"**Predicted App**: `{selected_row['application']}` (Confidence: `{selected_row['confidence']*100:.1f}%`)")
        st.markdown(f"**Attack Classification**: `{selected_row['attack_type']}` (Anomaly Score: `{selected_row['anomaly_score']:.2f}`)")
        st.markdown(f"**Final Threat Score**: `{selected_row['threat_score']}/100` (`{selected_row['threat_level']}`)")
        st.markdown(f"**Enforcement Decision**: `{selected_row['decision']}`")
    
    with col_b:
        st.markdown("**Explainable AI (XAI) Driver Features:**")
        xai_drivers = selected_row.get('xai_drivers', [])
        if xai_drivers:
            for feat in xai_drivers:
                st.markdown(f"- 🔹 **Key Feature Split**: `{feat}`")
        else:
            st.markdown("- Baseline benign traffic pattern")
            
        st.markdown(f"**Prediction Reason**: {selected_row['rationale']}")

else:
    st.info("No flows match the selected filter criteria.")
