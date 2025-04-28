import streamlit as st
import os
import yaml
import pandas as pd
from engine.feature_extractor import extract_features
from engine.model_predictor import predict_malware
from utils.hash_utils import compute_hashes
from engine.yara_scanner import run_yara_scan

# Import new modules if available
try:
    from engine.log_parser import parse_log_events, detect_log_anomalies
    from engine.case_manager import create_case, add_evidence, list_cases, get_case
    from engine.timeline_analyzer import create_event_timeline
    ADVANCED_FEATURES = True
except ImportError:
    ADVANCED_FEATURES = False

from engine.report_generator import generate_report

# Set page config
st.set_page_config(
    page_title="AI-Powered Cyberforensics Tool",
    page_icon="🔍",
    layout="wide"
)

# Initialize session state
if "cases" not in st.session_state:
    st.session_state.cases = []
    
if "current_case" not in st.session_state:
    st.session_state.current_case = None
    
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = {}

# Create directories
os.makedirs("data/samples", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("yara_rules", exist_ok=True)

if ADVANCED_FEATURES:
    os.makedirs("cases", exist_ok=True)

# Side Navigation
st.sidebar.title("🔍 Cyberforensics Tool")

# Main navigation options
nav_options = ["Dashboard", "File Analysis"]
if ADVANCED_FEATURES:
    nav_options.extend(["Log Analysis", "Case Management", "Timeline Analysis"])

# Main navigation
nav_option = st.sidebar.radio("Navigation", nav_options)

# Refresh cases list if case management is available
if ADVANCED_FEATURES and st.sidebar.button("Refresh Cases"):
    st.session_state.cases = list_cases()

# Case selector if available
if ADVANCED_FEATURES and st.session_state.cases:
    case_options = ["Select a case..."] + [f"{c['name']} ({c['id']})" for c in st.session_state.cases]
    case_selection = st.sidebar.selectbox("Active Case", case_options)
    
    if case_selection != "Select a case...":
        case_id = case_selection.split("(")[-1].strip(")")
        st.session_state.current_case = case_id

# Dashboard
if nav_option == "Dashboard":
    st.title("Cyberforensics Dashboard")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("Welcome to the AI-Powered Cyberforensics Tool")
        st.write("This tool helps you analyze suspicious files, logs, and build timelines for cybersecurity investigations.")
        
    with col2:
        st.subheader("Quick Start")
        st.write("1. Upload files for analysis")
        if ADVANCED_FEATURES:
            st.write("2. Create a case in Case Management")
            st.write("3. Analyze logs and create timelines")
            st.write("4. Generate comprehensive reports")
        else:
            st.write("2. Review analysis results")
            st.write("3. Download generated reports")
    
    # Stats
    st.subheader("Statistics")
    
    if ADVANCED_FEATURES:
        cases_count = len(list_cases())
    else:
        cases_count = "N/A"
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Cases", cases_count)
    col2.metric("Files Analyzed", 0)  # You'll need to track this
    col3.metric("Malware Detected", 0)  # You'll need to track this

# File Analysis
elif nav_option == "File Analysis":
    st.title("File Analysis")
    
    uploaded_file = st.file_uploader("Upload a file to analyze", type=None)
    
    if uploaded_file:
        # Save the file
        filepath = os.path.join("data", "samples", uploaded_file.name)
        with open(filepath, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        st.success(f"File uploaded: {uploaded_file.name}")
        
        # Analyze button
        if st.button("Analyze File"):
            with st.spinner("Analyzing file..."):
                # Extract features
                features = extract_features(filepath)
                
                # Predict malware
                prediction = predict_malware(features)
                
                # Compute hashes
                hashes = compute_hashes(filepath)
                
                # Run YARA scan
                yara_results = run_yara_scan(filepath)
                
                # Generate report
                report = generate_report(filepath, features, prediction, hashes, yara_results)
                
                # Add to case if one is selected and advanced features available
                if ADVANCED_FEATURES and st.session_state.current_case:
                    file_type = "malware" if "Malware" in prediction else "benign"
                    evidence_id = add_evidence(st.session_state.current_case, filepath, file_type)
                    if evidence_id:
                        st.success(f"Added to case {st.session_state.current_case} as evidence {evidence_id}")
                
                # Store results
                st.session_state.analysis_results = {
                    "features": features,
                    "prediction": prediction,
                    "hashes": hashes,
                    "yara_results": yara_results
                }
            
            # Display results
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Prediction")
                if "Malware" in str(prediction):
                    st.error(prediction)
                else:
                    st.success(prediction)
                
                st.subheader("Features")
                st.json(features)
            
            with col2:
                st.subheader("Hashes")
                st.json(hashes)
                
                st.subheader("YARA Matches")
                if yara_results:
                    st.json(yara_results)
                else:
                    st.write("No YARA matches found")
            
            st.success("Analysis complete! Report generated.")
            
            # Option to download the report
            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"{uploaded_file.name}_report.yaml",
                mime="text/yaml"
            )

# Log Analysis - only if advanced features are available
elif nav_option == "Log Analysis" and ADVANCED_FEATURES:
    st.title("Log Analysis")
    
    log_type = st.selectbox("Log Type", ["generic", "windows", "apache", "ssh"])
    
    uploaded_log = st.file_uploader("Upload a log file", type=["log", "txt"])
    
    if uploaded_log:
        # Save the log file
        filepath = os.path.join("data", "samples", uploaded_log.name)
        with open(filepath, "wb") as f:
            f.write(uploaded_log.getbuffer())
            
        st.success(f"Log file uploaded: {uploaded_log.name}")
        
        # Analyze button
        if st.button("Analyze Log"):
            with st.spinner("Analyzing log file..."):
                try:
                    # Read log content
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Parse log events
                    log_events = parse_log_events(content, log_type)
                    
                    # Detect anomalies
                    anomalies = detect_log_anomalies(log_events)
                    
                    # Add to case if one is selected
                    if st.session_state.current_case:
                        evidence_id = add_evidence(st.session_state.current_case, filepath, "log")
                        if evidence_id:
                            st.success(f"Added to case {st.session_state.current_case} as evidence {evidence_id}")
                    
                    # Store results
                    st.session_state.analysis_results = {
                        "events": log_events,
                        "anomalies": anomalies
                    }
                    
                except Exception as e:
                    st.error(f"Error analyzing log: {e}")
                    log_events = {}
                    anomalies = []
            
            # Display results
            st.subheader("Log Events")
            st.json(log_events)
            
            if anomalies:
                st.subheader("Anomalies Detected")
                for anomaly in anomalies:
                    st.warning(anomaly)
            else:
                st.success("No anomalies detected in the log file")

# Case Management - only if advanced features are available
elif nav_option == "Case Management" and ADVANCED_FEATURES:
    st.title("Case Management")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Create New Case")
        case_name = st.text_input("Case Name")
        case_desc = st.text_area("Description")
        investigator = st.text_input("Investigator")
        
        if st.button("Create Case"):
            if case_name:
                case = create_case(case_name, case_desc, investigator)
                st.session_state.current_case = case.id
                st.success(f"Case created: {case_name} (ID: {case.id})")
                st.session_state.cases = list_cases()
            else:
                st.error("Please enter a case name")
    
    with col2:
        st.subheader("Existing Cases")
        cases = list_cases()
        
        if not cases:
            st.info("No cases found")
        else:
            st.session_state.cases = cases
            
            # Display cases in a dataframe
            cases_df = pd.DataFrame([
                {
                    "ID": c["id"],
                    "Name": c["name"],
                    "Investigator": c["investigator"],
                    "Created": c["created_at"],
                    "Evidence Items": len(c["evidence"])
                }
                for c in cases
            ])
            
            st.dataframe(cases_df)
    
    # Case details (if selected)
    if st.session_state.current_case:
        case = get_case(st.session_state.current_case)
        if case:
            st.subheader(f"Case: {case.name}")
            
            tab1, tab2 = st.tabs(["Evidence", "Notes"])
            
            with tab1:
                if not case.evidence:
                    st.info("No evidence added to this case yet")
                else:
                    evidence_df = pd.DataFrame([
                        {
                            "ID": e["id"],
                            "Filename": e["filename"],
                            "Type": e["type"],
                            "Added": e["added_at"],
                            "Tags": ", ".join(e["tags"] if e["tags"] else [])
                        }
                        for e in case.evidence
                    ])
                    
                    st.dataframe(evidence_df)
            
            with tab2:
                st.info("Notes functionality coming soon")

# Timeline Analysis - only if advanced features are available
elif nav_option == "Timeline Analysis" and ADVANCED_FEATURES:
    st.title("Timeline Analysis")
    
    st.info("This feature is under development. Check back soon!")

# Footer
st.sidebar.divider()
st.sidebar.caption("AI-Powered Cyberforensics Tool")
st.sidebar.caption("© 2025 - v0.2")
