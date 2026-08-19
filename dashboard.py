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

# ── Consistent dark theme CSS ──
st.markdown("""
<style>
  html, body,
  [data-testid="stAppViewContainer"],
  [data-testid="stMain"], .main, section.main {
      background-color: #0D1117 !important;
  }
  [data-testid="stSidebar"] {
      background-color: #161B22 !important;
      border-right: 1px solid #30363D;
  }
  [data-testid="stMetric"] {
      background: linear-gradient(135deg, #1C2128 0%, #21262D 100%) !important;
      border: 1px solid #30363D !important;
      border-radius: 10px !important;
      padding: 14px 18px !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.4) !important;
  }
  [data-testid="stMetricLabel"]  { color: #8B949E !important; font-size: 0.78rem !important; }
  [data-testid="stMetricValue"]  { color: #E6EDF3 !important; font-weight: 700 !important; }
  h1, h2, h3, h4 { color: #E6EDF3 !important; }
  p, label, span { color: #C9D1D9; }
  [data-testid="stSidebar"] label,
  [data-testid="stSidebar"] p { color: #C9D1D9 !important; }
  [data-testid="stDataFrame"] { border: 1px solid #30363D; border-radius: 8px; }
  hr { border-color: #30363D; }
  .badge-critical { background:#7F1D1D; color:#FCA5A5; border-radius:4px; padding:2px 9px; font-weight:700; }
  .badge-high     { background:#7C2D12; color:#FDBA74; border-radius:4px; padding:2px 9px; font-weight:700; }
  .badge-medium   { background:#713F12; color:#FDE68A; border-radius:4px; padding:2px 9px; font-weight:700; }
  .badge-low      { background:#14532D; color:#86EFAC; border-radius:4px; padding:2px 9px; font-weight:700; }
  .badge-block    { background:#7F1D1D; color:#FCA5A5; border-radius:4px; padding:2px 9px; font-weight:700; }
  .badge-allow    { background:#14532D; color:#86EFAC; border-radius:4px; padding:2px 9px; font-weight:700; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI-Powered Deep Packet Inspection & Threat Detection")
st.caption("Real-Time Network Flow Traffic Analysis, Machine Learning Classification & Explainable AI Risk Matrix")

# Load Reports
REPORT_JSON = "reports/dpi_report.json"
REPORT_CSV = "reports/dpi_report.csv"

if not os.path.exists(REPORT_JSON) or not os.path.exists(REPORT_CSV):
    try:
        import generate_demo_report
    except Exception as e:
        st.warning(f"⚠️ Report file missing and auto-generation failed: {e}")
        st.stop()


with open(REPORT_JSON, 'r') as f:
    report_data = json.load(f)

summary = report_data.get('summary', {})
app_breakdown = report_data.get('app_breakdown', {})
df_flows = pd.DataFrame(report_data.get('flows', []))

# Sidebar Filters
st.sidebar.header("🔍 Flow Filters & Settings")

# --- Threat Level Filter (all levels always shown) ---
ALL_THREAT_LEVELS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
selected_threat_level = st.sidebar.selectbox(
    "⚠️ Threat Level",
    ALL_THREAT_LEVELS,
    help="Filter flows by their ML-assigned threat level"
)

# --- Enforcement Decision Filter ---
ALL_DECISIONS = ["ALL", "BLOCK", "ALLOW"]
selected_decision = st.sidebar.selectbox(
    "🚦 Enforcement Decision",
    ALL_DECISIONS,
    help="Filter by whether the flow was blocked or allowed"
)

# --- Application Type Filter (all 20 app types always shown) ---
ALL_APP_TYPES = [
    "ALL", "Amazon", "Apple", "Discord", "DNS",
    "Facebook", "GitHub", "Google", "HTTP", "HTTPS",
    "Instagram", "Microsoft", "Netflix", "Spotify", "Telegram",
    "TikTok", "Twitter", "UNKNOWN", "WhatsApp", "YouTube", "Zoom"
]
selected_app = st.sidebar.selectbox(
    "📱 Application Type",
    ALL_APP_TYPES,
    help="Filter flows by the ML-predicted application"
)

st.sidebar.markdown("---")
search_query = st.sidebar.text_input("🔎 Search IP / Domain / Reason", "", placeholder="e.g. 192.168.1.100")

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

# ── shared chart palette ──
BG_PAGE = "#0D1117"
BG_CARD = "#161B22"
BORDER  = "#30363D"
TXT     = "#C9D1D9"
MUTED   = "#8B949E"

# 2. Charts Row
c1, c2 = st.columns([1, 1])

with c1:
    st.subheader("📊 Application Traffic Distribution")
    if app_breakdown:
        import matplotlib.patches as mpatches
        df_app = pd.DataFrame(list(app_breakdown.items()), columns=["Application", "Packets"])
        df_app = df_app.sort_values(by="Packets", ascending=False)

        fig1, ax1 = plt.subplots(figsize=(6, 3.8))
        fig1.patch.set_facecolor(BG_CARD)
        ax1.set_facecolor(BG_PAGE)

        bar_colors = []
        for app in df_app["Application"]:
            if app == "UNKNOWN":                          bar_colors.append("#EF4444")
            elif app in ("HTTP", "HTTPS", "DNS"):         bar_colors.append("#3B82F6")
            else:                                         bar_colors.append("#22C55E")

        ax1.bar(df_app["Application"], df_app["Packets"], color=bar_colors, edgecolor=BG_CARD, linewidth=0.4)
        ax1.set_xlabel("Application", color=MUTED, fontsize=8)
        ax1.set_ylabel("Packets",     color=MUTED, fontsize=8)
        ax1.tick_params(axis="x", rotation=45, colors=TXT, labelsize=7)
        ax1.tick_params(axis="y",              colors=TXT, labelsize=7)
        for s in ax1.spines.values(): s.set_edgecolor(BORDER)
        ax1.spines["top"].set_visible(False)
        ax1.spines["right"].set_visible(False)
        legend_p = [
            mpatches.Patch(color="#22C55E", label="App Traffic"),
            mpatches.Patch(color="#3B82F6", label="Protocol (HTTP/DNS)"),
            mpatches.Patch(color="#EF4444", label="Unknown"),
        ]
        ax1.legend(handles=legend_p, fontsize=7, facecolor=BG_CARD, edgecolor=BORDER, labelcolor=TXT)
        fig1.tight_layout()
        st.pyplot(fig1)
        plt.close(fig1)
    else:
        st.info("No application data available.")

with c2:
    st.subheader("⚠️ Threat Score Distribution")
    if not df_flows.empty:
        import matplotlib.patches as mpatches
        fig2, ax2 = plt.subplots(figsize=(6, 3.8))
        fig2.patch.set_facecolor(BG_CARD)
        ax2.set_facecolor(BG_PAGE)

        n, bins, patches = ax2.hist(df_flows["threat_score"], bins=10, edgecolor=BG_CARD, linewidth=0.6)
        for i, p in enumerate(patches):
            if   bins[i] >= 80: p.set_facecolor("#DC2626")   # CRITICAL
            elif bins[i] >= 70: p.set_facecolor("#EF4444")   # HIGH
            elif bins[i] >= 40: p.set_facecolor("#F59E0B")   # MEDIUM
            else:               p.set_facecolor("#22C55E")   # LOW

        ax2.axvline(x=70, color="#EF4444", linestyle="--", linewidth=1.2, alpha=0.7)
        ax2.set_xlabel("Threat Score (0–100)", color=MUTED, fontsize=8)
        ax2.set_ylabel("Number of Flows",      color=MUTED, fontsize=8)
        ax2.tick_params(colors=TXT, labelsize=7)
        for s in ax2.spines.values(): s.set_edgecolor(BORDER)
        ax2.spines["top"].set_visible(False)
        ax2.spines["right"].set_visible(False)
        legend_p2 = [
            mpatches.Patch(color="#22C55E", label="LOW (0–39)"),
            mpatches.Patch(color="#F59E0B", label="MEDIUM (40–69)"),
            mpatches.Patch(color="#EF4444", label="HIGH (70–79)"),
            mpatches.Patch(color="#DC2626", label="CRITICAL (80+)"),
        ]
        ax2.legend(handles=legend_p2, fontsize=7, facecolor=BG_CARD, edgecolor=BORDER, labelcolor=TXT, loc="upper right")
        fig2.tight_layout()
        st.pyplot(fig2)
        plt.close(fig2)

st.markdown("---")

# 3. Threat Matrix & Explainable AI Table
st.subheader("🕵️ AI Flow Risk Matrix & Explainable AI (XAI) Drivers")

# Active filter summary
active = []
if selected_threat_level != "ALL": active.append(f"Threat: **{selected_threat_level}**")
if selected_decision     != "ALL": active.append(f"Decision: **{selected_decision}**")
if selected_app          != "ALL": active.append(f"App: **{selected_app}**")
if search_query:                   active.append(f'Search: **"{search_query}"**')
if active:
    st.caption("Active filters \u2192 " + "  |  ".join(active) + f"  \u2192  **{len(df_filtered)} flows**")
else:
    st.caption(f"Showing all **{len(df_filtered)} flows** (no filter active)")

if not df_filtered.empty:
    st.dataframe(
        df_filtered[[
            "flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
            "application", "threat_score", "threat_level", "confidence",
            "anomaly_score", "attack_type", "decision", "rationale"
        ]],
        use_container_width=True,   # will update to width='stretch' when dropping Streamlit <1.61 support
        height=320,
    )


    st.markdown("---")
    st.markdown("### 🔎 Flow Detail Inspector & Feature Drivers")
    selected_flow_id = st.selectbox("Select Flow ID to Inspect", df_filtered["flow_id"].unique())
    row = df_filtered[df_filtered["flow_id"] == selected_flow_id].iloc[0]

    def threat_badge(level):
        cls = {"CRITICAL":"badge-critical","HIGH":"badge-high","MEDIUM":"badge-medium","LOW":"badge-low"}.get(level,"badge-low")
        return f'<span class="{cls}">{level}</span>'

    def decision_badge(dec):
        return f'<span class="{"badge-block" if dec=="BLOCK" else "badge-allow"}">{dec}</span>'

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(f"**Flow ID**: `{row['flow_id']}`")
        st.markdown(f"**5-Tuple**: `{row['src_ip']}:{row['src_port']} ➔ {row['dst_ip']}:{row['dst_port']}` (Proto `{row['protocol']}`")
        st.markdown(f"**Predicted App**: `{row['application']}` &nbsp; Confidence: `{row['confidence']*100:.1f}%`")
        st.markdown(f"**Attack Type**: `{row['attack_type']}` &nbsp; Anomaly Score: `{row['anomaly_score']:.2f}`")
        st.markdown(
            f"**Threat Score**: `{row['threat_score']}/100` &nbsp; " + threat_badge(row['threat_level']),
            unsafe_allow_html=True
        )
        st.markdown(
            f"**Decision**: " + decision_badge(row['decision']),
            unsafe_allow_html=True
        )

    with col_b:
        st.markdown("**Explainable AI (XAI) Driver Features:**")
        xai = row.get("xai_drivers", [])
        if isinstance(xai, list) and xai:
            for feat in xai:
                st.markdown(f"- 🔹 Key Feature Split: `{feat}`")
        else:
            st.markdown("- Baseline benign traffic pattern")
        st.markdown(f"**Prediction Reason**: {row['rationale']}")

else:
    st.info("No flows match the selected filter criteria. Try changing the filters in the sidebar.")
