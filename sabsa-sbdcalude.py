import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional
import hashlib

# Enterprise Configuration
ENTERPRISE_CONFIG = {
    "company_name": "Fortune 100 Corp",
    "classification_levels": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
    "risk_appetite_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "compliance_frameworks": ["SOX", "PCI-DSS", "GDPR", "HIPAA", "ISO27001", "NIST", "SOC2"],
    "business_units": ["Finance", "HR", "IT", "Operations", "Legal", "Marketing", "R&D"],
    "geographic_regions": ["Americas", "EMEA", "APAC"]
}

# Data Models for Enterprise Features
@dataclass
class SecurityControl:
    control_id: str
    name: str
    description: str
    framework: str
    implementation_status: str
    risk_level: str
    owner: str
    last_assessment: str
    next_review: str
    cost: float
    effectiveness_score: float

@dataclass
class RiskAssessment:
    risk_id: str
    domain: str
    description: str
    likelihood: int
    impact: int
    risk_score: int
    mitigation_controls: List[str]
    owner: str
    status: str
    target_date: str

# Page configuration with enterprise theming
st.set_page_config(
    page_title="Enterprise Security Architecture Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise CSS with professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1a365d;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: 700;
    }
    .executive-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 12px;
        margin: 10px 0;
        box-shadow: 0 8px 16px rgba(0,0,0,0.1);
    }
    .risk-critical { background-color: #fee2e2; border-left: 4px solid #dc2626; }
    .risk-high { background-color: #fef3c7; border-left: 4px solid #f59e0b; }
    .risk-medium { background-color: #dbeafe; border-left: 4px solid #3b82f6; }
    .risk-low { background-color: #d1fae5; border-left: 4px solid #10b981; }
    .compliance-compliant { color: #10b981; font-weight: bold; }
    .compliance-non-compliant { color: #dc2626; font-weight: bold; }
    .compliance-partial { color: #f59e0b; font-weight: bold; }
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        border-left: 4px solid #3b82f6;
        margin: 10px 0;
    }
    .alert-banner {
        background-color: #fef2f2;
        border: 1px solid #fecaca;
        color: #991b1b;
        padding: 12px;
        border-radius: 8px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# Enterprise Authentication and RBAC
class EnterpriseAuth:
    def __init__(self):
        self.roles = {
            "CISO": ["read", "write", "admin", "approve"],
            "Security_Architect": ["read", "write", "design"],
            "Security_Manager": ["read", "write", "manage"],
            "Security_Analyst": ["read", "analyze"],
            "Auditor": ["read", "audit"],
            "Executive": ["read", "executive"]
        }
    
    def authenticate_user(self, username: str, role: str) -> bool:
        if not hasattr(st.session_state, 'authenticated'):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.username = None
        
        return st.session_state.authenticated
    
    def check_permission(self, required_permission: str) -> bool:
        if not st.session_state.authenticated:
            return False
        
        # Allow executives and CISOs to access executive dashboard
        if required_permission == "executive":
            return st.session_state.user_role in ["Executive", "CISO"]
        
        # Allow managers to access management functions
        if required_permission == "manage":
            return st.session_state.user_role in ["CISO", "Security_Manager", "Security_Architect"]
        
        # Allow auditors to access audit functions
        if required_permission == "audit":
            return st.session_state.user_role in ["Auditor", "CISO", "Security_Manager"]
        
        # Allow analysts to access analysis functions
        if required_permission == "analyze":
            return st.session_state.user_role in ["Security_Analyst", "CISO", "Security_Manager", "Security_Architect"]
        
        # Allow admins to access admin functions
        if required_permission == "admin":
            return st.session_state.user_role in ["CISO"]
        
        # Default permission check
        user_permissions = self.roles.get(st.session_state.user_role, [])
        return required_permission in user_permissions

# Enterprise Data Management
class EnterpriseDataManager:
    def __init__(self):
        self.init_sample_data()
    
    def init_sample_data(self):
        if 'security_controls' not in st.session_state:
            st.session_state.security_controls = [
                {
                    'control_id': 'CTRL-001',
                    'name': 'Data Encryption',
                    'description': 'Encryption of data at rest and in transit',
                    'framework': 'ISO27001',
                    'implementation_status': 'Implemented',
                    'risk_level': 'HIGH',
                    'owner': 'Security Team',
                    'last_assessment': '2024-01-01',
                    'next_review': '2024-07-01',
                    'cost': 150000.0,
                    'effectiveness_score': 95.0
                }
            ]
        
        if 'risk_assessments' not in st.session_state:
            st.session_state.risk_assessments = [
                {
                    'risk_id': 'RSK-001',
                    'domain': 'Data Security',
                    'description': 'Data breach via third-party vendor',
                    'likelihood': 2,
                    'impact': 3,
                    'risk_score': 6,
                    'mitigation_controls': ['CTRL-001'],
                    'owner': 'CISO',
                    'status': 'Open',
                    'target_date': '2024-03-01'
                }
            ]
    
    def get_security_controls(self) -> List[dict]:
        return st.session_state.security_controls
    
    def get_risk_assessments(self) -> List[dict]:
        return st.session_state.risk_assessments

# Executive Dashboard
def create_executive_dashboard():
    st.markdown('<h1 class="main-header">🛡️ Executive Security Dashboard</h1>', unsafe_allow_html=True)
    
    # Check executive permissions
    auth = EnterpriseAuth()
    if not auth.check_permission("executive"):
        st.error("Access Denied: Executive privileges required")
        return
    
    # Key Security Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Security Posture Score", "87.3%", "↑ 2.1%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Critical Risks", "3", "↓ 2")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Compliance Score", "94.2%", "↑ 1.8%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Security Budget Utilization", "78.5%", "↑ 5.2%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Risk and Compliance Overview
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Security Risks")
        risks_data = [
            {"Risk": "Third-party Data Breach", "Score": 9, "Owner": "J. Smith", "Due": "2024-02-15"},
            {"Risk": "Insider Threat", "Score": 8, "Owner": "M. Johnson", "Due": "2024-02-20"},
            {"Risk": "Ransomware Attack", "Score": 8, "Owner": "A. Davis", "Due": "2024-02-25"}
        ]
        
        for risk in risks_data:
            risk_class = "risk-critical" if risk["Score"] >= 9 else "risk-high" if risk["Score"] >= 7 else "risk-medium"
            st.markdown(f'''
            <div class="{risk_class}" style="padding: 10px; margin: 5px 0; border-radius: 5px;">
                <strong>{risk["Risk"]}</strong> (Score: {risk["Score"]})<br>
                Owner: {risk["Owner"]} | Due: {risk["Due"]}
            </div>
            ''', unsafe_allow_html=True)
    
    with col2:
        st.subheader("Compliance Status by Framework")
        compliance_data = [
            {"Framework": "SOX", "Status": "Compliant", "Score": 98.5},
            {"Framework": "PCI-DSS", "Status": "Compliant", "Score": 96.2},
            {"Framework": "GDPR", "Status": "Partial", "Score": 89.7}
        ]
        
        for comp in compliance_data:
            status_class = "compliance-compliant" if comp["Status"] == "Compliant" else "compliance-partial"
            st.markdown(f'''
            <div class="metric-card">
                <strong>{comp["Framework"]}</strong><br>
                <span class="{status_class}">{comp["Status"]}</span> - {comp["Score"]}%
            </div>
            ''', unsafe_allow_html=True)

# Risk Management Module
def create_risk_management_module():
    st.header("🎯 Enterprise Risk Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("manage"):
        st.error("Access Denied: Management privileges required")
        return
    
    st.subheader("Risk Register")
    
    # Risk entry form
    with st.expander("Add New Risk"):
        col1, col2 = st.columns(2)
        with col1:
            risk_domain = st.selectbox("Domain", ["Data Security", "Identity & Access Management", 
                                                "Incident Response", "Vulnerability Management"])
            risk_description = st.text_area("Risk Description")
            likelihood = st.selectbox("Likelihood", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
        
        with col2:
            impact = st.selectbox("Impact", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
            risk_owner = st.selectbox("Risk Owner", ["CISO", "Security Manager", "IT Director"])
            target_date = st.date_input("Target Mitigation Date")
        
        if st.button("Add Risk"):
            new_risk = {
                'risk_id': f'RSK-{len(st.session_state.risk_assessments) + 1:03d}',
                'domain': risk_domain,
                'description': risk_description,
                'likelihood': likelihood,
                'impact': impact,
                'risk_score': likelihood * impact,
                'mitigation_controls': [],
                'owner': risk_owner,
                'status': 'Open',
                'target_date': str(target_date)
            }
            
            st.session_state.risk_assessments.append(new_risk)
            st.success(f"Risk added successfully!")
            st.rerun()
    
    # Display existing risks
    data_manager = EnterpriseDataManager()
    risks = data_manager.get_risk_assessments()
    
    if risks:
        risk_display_data = []
        for risk in risks:
            risk_display_data.append({
                "ID": risk['risk_id'],
                "Domain": risk['domain'],
                "Description": risk['description'],
                "Likelihood": risk['likelihood'],
                "Impact": risk['impact'],
                "Score": risk['risk_score'],
                "Owner": risk['owner'],
                "Status": risk['status']
            })
        
        df_risks = pd.DataFrame(risk_display_data)
        st.dataframe(df_risks, use_container_width=True)
    else:
        st.info("No risks in the register yet.")

# Compliance Module
def create_compliance_module():
    st.header("📋 Compliance Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("audit"):
        st.error("Access Denied: Audit privileges required")
        return
    
    st.subheader("Regulatory Framework Mapping")
    
    # Framework selection
    selected_framework = st.selectbox("Select Compliance Framework", 
                                    ENTERPRISE_CONFIG["compliance_frameworks"])
    
    # Sample compliance mapping
    compliance_mappings = {
        "SOX": [
            {"Requirement": "ITGC-001", "Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
            {"Requirement": "ITGC-002", "Domain": "Identity & Access Management", "Control": "Access Reviews", "Status": "Compliant"}
        ],
        "PCI-DSS": [
            {"Requirement": "PCI-3.4", "Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
            {"Requirement": "PCI-8.1", "Domain": "Identity & Access Management", "Control": "User Authentication", "Status": "Compliant"}
        ]
    }
    
    if selected_framework in compliance_mappings:
        df_compliance = pd.DataFrame(compliance_mappings[selected_framework])
        st.dataframe(df_compliance, use_container_width=True)
    else:
        st.info(f"Compliance mapping for {selected_framework} not yet configured.")

# Metrics Dashboard
def create_metrics_dashboard():
    st.header("📊 Security Metrics & KPIs")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Mean Time to Detection", "4.2 hours", "↓ 0.5 hours")
    with col2:
        st.metric("Mean Time to Response", "23 minutes", "↓ 5 minutes")
    with col3:
        st.metric("Security ROI", "315%", "↑ 15%")
    
    # Sample chart
    dates = pd.date_range(start='2023-01-01', end='2024-01-01', freq='M')
    values = np.random.randint(10, 50, len(dates))
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=dates, y=values, mode='lines+markers', name='Security Events'))
    fig.update_layout(title="Security Events Trend", xaxis_title="Date", yaxis_title="Count")
    st.plotly_chart(fig, use_container_width=True)

# SABSA Framework
def create_sabsa_framework():
    st.header("🔒 SABSA Security Architecture Framework")
    
    st.info("Interactive SABSA framework visualization and analysis tools")
    
    tabs = st.tabs(["Contextual", "Conceptual", "Logical", "Physical"])
    
    with tabs[0]:
        st.subheader("Contextual Security Architecture")
        st.write("What assets do we need to protect and why?")
        
        business_drivers = {
            'Driver': ['Regulatory Compliance', 'Customer Trust', 'Intellectual Property'],
            'Priority': ['Critical', 'High', 'High'],
            'Impact Score': [95, 85, 80]
        }
        
        df_drivers = pd.DataFrame(business_drivers)
        st.dataframe(df_drivers, use_container_width=True)
    
    with tabs[1]:
        st.subheader("Conceptual Security Architecture")
        st.write("What do we need to do to protect our assets?")
        
        concepts = ['Authentication', 'Authorization', 'Audit', 'Availability']
        
        for concept in concepts:
            with st.expander(f"{concept}"):
                st.write(f"Implementation strategy and controls for {concept}")
    
    with tabs[2]:
        st.subheader("Logical Security Architecture")
        st.write("How can we structure our security solution?")
        
        st.markdown("""
        ### Security Domains
        - **Perimeter Security**: Firewalls, IPS, WAF
        - **Identity Management**: SSO, MFA, PAM
        - **Data Security**: Encryption, DLP, Classification
        - **Endpoint Security**: EDR, Mobile Security
        """)
    
    with tabs[3]:
        st.subheader("Physical Security Architecture")
        st.write("What security products and tools will we use?")
        
        tools_data = {
            'Category': ['SIEM', 'Firewall', 'Identity Management'],
            'Product': ['Splunk', 'Palo Alto', 'Okta'],
            'Status': ['Deployed', 'Deployed', 'Deployed']
        }
        
        df_tools = pd.DataFrame(tools_data)
        st.dataframe(df_tools, use_container_width=True)

# Main application
def main():
    # Initialize session state for authentication
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_role = None
        st.session_state.username = None
    
    # Authentication UI
    if not st.session_state.authenticated:
        st.title("🛡️ Enterprise Security Architecture Platform")
        st.subheader("Please authenticate to continue")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            username = st.text_input("Username")
            role = st.selectbox("Role", ["CISO", "Security_Architect", "Security_Manager", "Security_Analyst", "Auditor", "Executive"])
            
            if st.button("Login", type="primary"):
                st.session_state.authenticated = True
                st.session_state.user_role = role
                st.session_state.username = username
                st.rerun()
        return
    
    # Main application interface
    st.sidebar.title(f"👤 {st.session_state.username}")
    st.sidebar.write(f"Role: {st.session_state.user_role}")
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()
    
    # Navigation based on role
    navigation_options = {
        "CISO": ["Executive Dashboard", "Risk Management", "Compliance", "Metrics & KPIs", "SABSA Framework"],
        "Security_Architect": ["SABSA Framework", "Risk Management", "Metrics & KPIs"],
        "Security_Manager": ["Risk Management", "Compliance", "Metrics & KPIs", "SABSA Framework"],
        "Security_Analyst": ["Risk Management", "SABSA Framework", "Metrics & KPIs"],
        "Auditor": ["Compliance", "Risk Management", "Metrics & KPIs", "SABSA Framework"],
        "Executive": ["Executive Dashboard", "Metrics & KPIs", "Risk Management"]
    }
    
    available_options = navigation_options.get(st.session_state.user_role, ["SABSA Framework"])
    selected_page = st.sidebar.selectbox("Navigation", available_options)
    
    # Page routing
    if selected_page == "Executive Dashboard":
        create_executive_dashboard()
    elif selected_page == "Risk Management":
        create_risk_management_module()
    elif selected_page == "Compliance":
        create_compliance_module()
    elif selected_page == "Metrics & KPIs":
        create_metrics_dashboard()
    elif selected_page == "SABSA Framework":
        create_sabsa_framework()
    
    # Global alerts
    st.sidebar.markdown("---")
    st.sidebar.subheader("🚨 Security Alerts")
    st.sidebar.error("3 critical vulnerabilities require attention")
    st.sidebar.warning("Compliance audit scheduled for next week")
    st.sidebar.info("Security training completion: 96.8%")

if __name__ == "__main__":
    main()
