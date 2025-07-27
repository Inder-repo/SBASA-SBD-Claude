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

@dataclass
class ComplianceMapping:
    framework: str
    requirement: str
    sabsa_domain: str
    control_id: str
    compliance_status: str
    evidence: str
    auditor_notes: str

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

# Rest of your code remains exactly the same...
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
        user_permissions = self.roles.get(st.session_state.user_role, [])
        
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
        
        return required_permission in user_permissions

# Enterprise Data Management (Using session state instead of SQLite for Streamlit compatibility)
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
                },
                {
                    'control_id': 'CTRL-002',
                    'name': 'Multi-Factor Authentication',
                    'description': 'MFA for all privileged accounts',
                    'framework': 'NIST',
                    'implementation_status': 'Implemented',
                    'risk_level': 'HIGH',
                    'owner': 'Identity Team',
                    'last_assessment': '2024-01-15',
                    'next_review': '2024-07-15',
                    'cost': 75000.0,
                    'effectiveness_score': 92.0
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
                    'mitigation_controls': ['CTRL-001', 'CTRL-002'],
                    'owner': 'CISO',
                    'status': 'Open',
                    'target_date': '2024-03-01'
                },
                {
                    'risk_id': 'RSK-002',
                    'domain': 'Identity & Access Management',
                    'description': 'Privileged account compromise',
                    'likelihood': 1,
                    'impact': 3,
                    'risk_score': 3,
                    'mitigation_controls': ['CTRL-002'],
                    'owner': 'Security Manager',
                    'status': 'Mitigating',
                    'target_date': '2024-02-15'
                }
            ]
    
    def get_security_controls(self) -> List[dict]:
        return st.session_state.security_controls
    
    def get_risk_assessments(self) -> List[dict]:
        return st.session_state.risk_assessments

# Enterprise Risk Engine
class EnterpriseRiskEngine:
    def __init__(self):
        self.risk_matrix = {
            (1, 1): ("LOW", "#10b981"), (1, 2): ("LOW", "#10b981"), (1, 3): ("MEDIUM", "#3b82f6"),
            (2, 1): ("LOW", "#10b981"), (2, 2): ("MEDIUM", "#3b82f6"), (2, 3): ("HIGH", "#f59e0b"),
            (3, 1): ("MEDIUM", "#3b82f6"), (3, 2): ("HIGH", "#f59e0b"), (3, 3): ("CRITICAL", "#dc2626")
        }
    
    def calculate_risk_score(self, likelihood: int, impact: int) -> tuple:
        score = likelihood * impact
        risk_level, color = self.risk_matrix.get((likelihood, impact), ("UNKNOWN", "#6b7280"))
        return score, risk_level, color
    
    def generate_risk_heatmap(self, risks: List[dict]):
        likelihood_vals = [r['likelihood'] for r in risks]
        impact_vals = [r['impact'] for r in risks]
        risk_scores = [r['risk_score'] for r in risks]
        domains = [r['domain'] for r in risks]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=likelihood_vals,
            y=impact_vals,
            mode='markers+text',
            marker=dict(
                size=[score * 5 for score in risk_scores],
                color=risk_scores,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Risk Score")
            ),
            text=domains,
            textposition="top center",
            hovertemplate='<b>%{text}</b><br>Likelihood: %{x}<br>Impact: %{y}<br>Score: %{marker.color}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Enterprise Risk Heatmap",
            xaxis_title="Likelihood",
            yaxis_title="Impact",
            xaxis=dict(range=[0.5, 3.5], dtick=1),
            yaxis=dict(range=[0.5, 3.5], dtick=1),
            height=500
        )
        
        return fig

# Integration with Enterprise Systems (Mock data for Streamlit)
class EnterpriseIntegrations:
    def __init__(self):
        self.integrations = {
            "ServiceNow": {"status": "Connected", "last_sync": "2024-01-15 09:30"},
            "Splunk": {"status": "Connected", "last_sync": "2024-01-15 09:25"},
            "CyberArk": {"status": "Connected", "last_sync": "2024-01-15 09:20"},
            "Qualys": {"status": "Connected", "last_sync": "2024-01-15 09:15"},
            "Archer GRC": {"status": "Connected", "last_sync": "2024-01-15 09:10"},
            "Microsoft Sentinel": {"status": "Connected", "last_sync": "2024-01-15 09:05"},
            "Okta": {"status": "Connected", "last_sync": "2024-01-15 09:00"}
        }
    
    def sync_with_servicenow(self):
        return {"incidents": 45, "changes": 12, "problems": 3}
    
    def sync_with_splunk(self):
        return {"alerts": 234, "events": 1500000, "threats": 12}
    
    def sync_with_grc_platform(self):
        return {"open_findings": 67, "overdue_reviews": 8, "compliance_score": 94.2}

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
            {"Risk": "Ransomware Attack", "Score": 8, "Owner": "A. Davis", "Due": "2024-02-25"},
            {"Risk": "Cloud Misconfiguration", "Score": 7, "Owner": "R. Wilson", "Due": "2024-03-01"},
            {"Risk": "Supply Chain Attack", "Score": 7, "Owner": "L. Brown", "Due": "2024-03-05"}
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
            {"Framework": "GDPR", "Status": "Partial", "Score": 89.7},
            {"Framework": "ISO27001", "Status": "Compliant", "Score": 94.8},
            {"Framework": "NIST", "Status": "Partial", "Score": 87.3}
        ]
        
        for comp in compliance_data:
            status_class = "compliance-compliant" if comp["Status"] == "Compliant" else "compliance-partial"
            st.markdown(f'''
            <div class="metric-card">
                <strong>{comp["Framework"]}</strong><br>
                <span class="{status_class}">{comp["Status"]}</span> - {comp["Score"]}%
            </div>
            ''', unsafe_allow_html=True)
    
    # Budget and ROI Analysis
    st.subheader("Security Investment Analysis")
    
    budget_data = {
        'Category': ['Personnel', 'Technology', 'Training', 'Consulting', 'Compliance'],
        'Allocated': [12.5, 8.3, 1.2, 2.1, 1.5],
        'Spent': [11.8, 7.9, 1.0, 1.9, 1.3],
        'ROI_Score': [85, 92, 78, 88, 91]
    }
    
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Budget Allocation vs Spending ($M)', 'Security ROI by Category'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    fig.add_trace(
        go.Bar(name='Allocated', x=budget_data['Category'], y=budget_data['Allocated']),
        row=1, col=1
    )
    fig.add_trace(
        go.Bar(name='Spent', x=budget_data['Category'], y=budget_data['Spent']),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(x=budget_data['Category'], y=budget_data['ROI_Score'], 
                  mode='lines+markers', name='ROI Score'),
        row=1, col=2
    )
    
    fig.update_layout(height=400, showlegend=True)
    st.plotly_chart(fig, use_container_width=True)

# Advanced Risk Management
def create_risk_management_module():
    st.header("🎯 Enterprise Risk Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("manage"):
        st.error("Access Denied: Management privileges required")
        return
    
    tabs = st.tabs(["Risk Register", "Risk Analysis", "Mitigation Planning", "Risk Reporting"])
    
    with tabs[0]:
        st.subheader("Enterprise Risk Register")
        
        # Risk entry form
        with st.expander("Add New Risk"):
            col1, col2 = st.columns(2)
            with col1:
                risk_domain = st.selectbox("Domain", ["Data Security", "Identity & Access Management", 
                                                    "Incident Response", "Vulnerability Management", 
                                                    "Security Risk Management"])
                risk_description = st.text_area("Risk Description")
                likelihood = st.selectbox("Likelihood", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
            
            with col2:
                impact = st.selectbox("Impact", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
                risk_owner = st.selectbox("Risk Owner", ["CISO", "Security Manager", "IT Director", "Business Owner"])
                target_date = st.date_input("Target Mitigation Date")
            
            if st.button("Add Risk"):
                risk_engine = EnterpriseRiskEngine()
                score, level, color = risk_engine.calculate_risk_score(likelihood, impact)
                
                # Add to session state
                new_risk = {
                    'risk_id': f'RSK-{len(st.session_state.risk_assessments) + 1:03d}',
                    'domain': risk_domain,
                    'description': risk_description,
                    'likelihood': likelihood,
                    'impact': impact,
                    'risk_score': score,
                    'mitigation_controls': [],
                    'owner': risk_owner,
                    'status': 'Open',
                    'target_date': str(target_date)
                }
                
                st.session_state.risk_assessments.append(new_risk)
                st.success(f"Risk added with score: {score} ({level})")
                st.rerun()
        
        # Risk register table
        data_manager = EnterpriseDataManager()
        risks = data_manager.get_risk_assessments()
        
        if risks:
            risk_display_data = []
            for risk in risks:
                risk_engine = EnterpriseRiskEngine()
                _, level, _ = risk_engine.calculate_risk_score(risk['likelihood'], risk['impact'])
                
                risk_display_data.append({
                    "ID": risk['risk_id'],
                    "Domain": risk['domain'],
                    "Description": risk['description'],
                    "Likelihood": risk['likelihood'],
                    "Impact": risk['impact'],
                    "Score": risk['risk_score'],
                    "Level": level,
                    "Owner": risk['owner'],
                    "Status": risk['status']
                })
            
            df_risks = pd.DataFrame(risk_display_data)
            st.dataframe(df_risks, use_container_width=True)
        else:
            st.info("No risks in the register yet.")
    
    with tabs[1]:
        st.subheader("Risk Analysis & Heat Map")
        
        data_manager = EnterpriseDataManager()
        risks = data_manager.get_risk_assessments()
        
        if risks:
            risk_engine = EnterpriseRiskEngine()
            heatmap = risk_engine.generate_risk_heatmap(risks)
            st.plotly_chart(heatmap, use_container_width=True)
        
        # Risk trend analysis
        st.subheader("Risk Trend Analysis")
        dates = pd.date_range(start='2023-01-01', end='2024-01-01', freq='M')
        risk_counts = np.random.randint(10, 50, len(dates))
        
        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(x=dates, y=risk_counts, mode='lines+markers', name='Risk Count'))
        fig_trend.update_layout(title="Risk Count Trend Over Time", xaxis_title="Date", yaxis_title="Number of Risks")
        st.plotly_chart(fig_trend, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Risk Mitigation Planning")
        
        # Mitigation strategy matrix
        mitigation_strategies = {
            "Accept": {"Cost": "Low", "Time": "Immediate", "Effectiveness": "Low"},
            "Avoid": {"Cost": "High", "Time": "Long", "Effectiveness": "High"},
            "Mitigate": {"Cost": "Medium", "Time": "Medium", "Effectiveness": "Medium"},
            "Transfer": {"Cost": "Medium", "Time": "Short", "Effectiveness": "Medium"}
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Mitigation Strategies")
            for strategy, details in mitigation_strategies.items():
                st.write(f"**{strategy}**: Cost: {details['Cost']}, Time: {details['Time']}, Effectiveness: {details['Effectiveness']}")
        
        with col2:
            st.subheader("Control Effectiveness Analysis")
            control_data = {
                'Control': ['Data Encryption', 'MFA', 'SIEM', 'DLP', 'PAM'],
                'Effectiveness': [95, 92, 88, 85, 90],
                'Cost': [100, 50, 200, 150, 120]
            }
            
            fig_controls = go.Figure()
            fig_controls.add_trace(go.Scatter(
                x=control_data['Cost'], 
                y=control_data['Effectiveness'],
                mode='markers+text',
                text=control_data['Control'],
                textposition="top center",
                marker=dict(size=15, color='blue')
            ))
            fig_controls.update_layout(
                title="Control Cost vs Effectiveness",
                xaxis_title="Cost ($K)",
                yaxis_title="Effectiveness (%)"
            )
            st.plotly_chart(fig_controls, use_container_width=True)
    
    with tabs[3]:
        st.subheader("Executive Risk Reporting")
        
        # Generate executive risk report
        if st.button("Generate Executive Risk Report"):
            st.markdown("""
            ## Executive Risk Summary
            
            ### Key Findings:
            - **3 Critical Risks** requiring immediate attention
            - **12 High Risks** with mitigation plans in progress
            - **Risk posture improved 15%** over last quarter
            
            ### Top Recommendations:
            1. Accelerate third-party risk assessment program
            2. Increase investment in identity management controls
            3. Enhance incident response capabilities
            
            ### Budget Impact:
            - Additional $2.3M required for critical risk mitigation
            - Expected ROI: 300% over 2 years
            - Regulatory compliance maintained at 94%
            """)

# Compliance Management
def create_compliance_module():
    st.header("📋 Compliance Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("audit"):
        st.error("Access Denied: Audit privileges required")
        return
    
    tabs = st.tabs(["Framework Mapping", "Control Assessment", "Audit Management", "Compliance Reporting"])
    
    with tabs[0]:
        st.subheader("Regulatory Framework Mapping")
        
        # Framework selection
        selected_framework = st.selectbox("Select Compliance Framework", 
                                        ENTERPRISE_CONFIG["compliance_frameworks"])
        
        # Sample compliance mapping
        compliance_mappings = {
            "SOX": [
                {"Requirement": "ITGC-001", "SABSA Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
                {"Requirement": "ITGC-002", "SABSA Domain": "Identity & Access Management", "Control": "Access Reviews", "Status": "Compliant"},
                {"Requirement": "ITGC-003", "SABSA Domain": "Incident Response", "Control": "Change Management", "Status": "Partial"}
            ],
            "PCI-DSS": [
                {"Requirement": "PCI-3.4", "SABSA Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
                {"Requirement": "PCI-8.1", "SABSA Domain": "Identity & Access Management", "Control": "User Authentication", "Status": "Compliant"},
                {"Requirement": "PCI-11.1", "SABSA Domain": "Vulnerability Management", "Control": "Vulnerability Scanning", "Status": "Compliant"}
            ],
            "GDPR": [
                {"Requirement": "Art. 32", "SABSA Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
                {"Requirement": "Art. 25", "SABSA Domain": "Data Security", "Control": "Privacy by Design", "Status": "Partial"},
                {"Requirement": "Art. 33", "SABSA Domain": "Incident Response", "Control": "Breach Notification", "Status": "Compliant"}
            ]
        }
        
        if selected_framework in compliance_mappings:
            df_compliance = pd.DataFrame(compliance_mappings[selected_framework])
            st.dataframe(df_compliance, use_container_width=True)
        else:
            st.info(f"Compliance mapping for {selected_framework} not yet configured.")
    
    with tabs[1]:
        st.subheader("Control Assessment")
        
        # Control assessment form
        with st.expander("Submit Control Assessment"):
            col1, col2 = st.columns(2)
            
            with col1:
                control_id = st.text_input("Control ID")
                control_name = st.text_input("Control Name")
                assessment_date = st.date_input("Assessment Date")
            
            with col2:
                effectiveness = st.selectbox("Control Effectiveness", ["Ineffective", "Partially Effective", "Effective"])
                test_result = st.selectbox("Test Result", ["Pass", "Fail", "Exception"])
                next_review = st.date_input("Next Review Date")
            
            if st.button("Submit Assessment"):
                st.success("Control assessment submitted successfully")
        
        # Assessment results summary
        st.subheader("Assessment Results Summary")
        assessment_data = {
            'Control Category': ['Access Control', 'Data Protection', 'Monitoring', 'Incident Response', 'Risk Management'],
            'Total Controls': [25, 18, 15, 12, 20],
            'Effective': [23, 17, 14, 11, 18],
            'Partially Effective': [2, 1, 1, 1, 2],
            'Ineffective': [0, 0, 0, 0, 0]
        }
        
        df_assessment = pd.DataFrame(assessment_data)
        st.dataframe(df_assessment, use_container_width=True)
        
        # Control effectiveness chart
        fig_assessment = go.Figure()
        fig_assessment.add_trace(go.Bar(name='Effective', x=assessment_data['Control Category'], y=assessment_data['Effective'], marker_color='green'))
        fig_assessment.add_trace(go.Bar(name='Partially Effective', x=assessment_data['Control Category'], y=assessment_data['Partially Effective'], marker_color='orange'))
        fig_assessment.add_trace(go.Bar(name='Ineffective', x=assessment_data['Control Category'], y=assessment_data['Ineffective'], marker_color='red'))
        
        fig_assessment.update_layout(
            title="Control Effectiveness by Category",
            xaxis_title="Control Category",
            yaxis_title="Number of Controls",
            barmode='stack'
        )
        st.plotly_chart(fig_assessment, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Audit Management")
