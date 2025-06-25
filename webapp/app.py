import streamlit as st
import os
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import your engine components
from engine.feature_extractor import extract_features, extract_advanced_features
from engine.model_predictor import predict_malware
from engine.yara_scanner import run_yara_scan
from utils.hash_utils import compute_hashes
from engine.report_generator import generate_report

st.set_page_config(page_title="AI Cyberforensics Tool", layout="wide")

st.title("AI-Powered Cyberforensics Tool")
st.write("Upload files for malware analysis, log examination, and memory forensics")

# Create tabs for different analysis types
tab1, tab2, tab3, tab4 = st.tabs(["File Analysis", "Log Analysis", "Memory Analysis", "Timeline"])

with tab1:
    st.header("File Analysis")
    uploaded_file = st.file_uploader("Choose a file for analysis", type=None)
    
    if uploaded_file is not None:
        # Save the uploaded file temporarily
        temp_file_path = os.path.join("temp", uploaded_file.name)
        os.makedirs("temp", exist_ok=True)
        
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        if st.button("Analyze File"):
            with st.spinner("Analyzing file..."):
                # Extract features
                features = extract_features(temp_file_path)
                adv_features = extract_advanced_features(temp_file_path)
                
                # Run prediction
                prediction = predict_malware(adv_features)
                
                # Compute hashes
                hashes = compute_hashes(temp_file_path)
                
                # Run YARA scan
                yara_matches = run_yara_scan(temp_file_path)
                
                # Display results
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Basic Information")
                    st.write(f"**File:** {uploaded_file.name}")
                    st.write(f"**Size:** {features.get('file_size', 0)} bytes")
                    st.write(f"**Entropy:** {features.get('entropy', 0)}")
                    
                    st.subheader("Hash Values")
                    for hash_type, hash_value in hashes.items():
                        st.write(f"**{hash_type}:** {hash_value}")
                
                with col2:
                    st.subheader("Analysis Results")
                    
                    # Show prediction with color
                    if "Malware" in prediction or "Suspicious" in prediction:
                        st.error(f"**Prediction:** {prediction}")
                    else:
                        st.success(f"**Prediction:** {prediction}")
                    
                    st.subheader("YARA Matches")
                    if yara_matches:
                        for match in yara_matches:
                            st.warning(f"- {match}")
                    else:
                        st.write("No YARA rules matched")
                
                st.subheader("Advanced Features")
                if adv_features.get('suspicious_api_count', 0) > 0:
                    st.warning(f"Suspicious API References: {adv_features.get('suspicious_api_count', 0)}")
                if adv_features.get('suspicious_term_count', 0) > 0:
                    st.warning(f"Suspicious Terms: {adv_features.get('suspicious_term_count', 0)}")

with tab2:
    st.header("Log Analysis")
    uploaded_log = st.file_uploader("Upload a Windows Security log (CSV format preferred)", type=["csv", "log", "txt", "xml"], key="log_uploader")
    
    if uploaded_log is not None:
        temp_log_path = os.path.join("temp", uploaded_log.name)
        os.makedirs("temp", exist_ok=True)
        with open(temp_log_path, "wb") as f:
            f.write(uploaded_log.getbuffer())
        
        log_type = st.selectbox(
            "Select log type", 
            ["windows", "apache", "ssh", "generic"]
        )
        
        if st.button("Analyze Log"):
            with st.spinner("Analyzing log file..."):
                try:
                    if log_type == "windows":
                        # Corrected: removed 'errors' argument
                        df = pd.read_csv(temp_log_path, encoding="utf-8")
                        st.write("Log file loaded. Showing first 5 rows:")
                        st.dataframe(df.head())

                        # Look for failed login attempts (Event ID 4625)
                        if "EventID" in df.columns:
                            failed_logins = df[df["EventID"] == 4625]
                        else:
                            # Try to find event id in another column
                            failed_logins = df[df.apply(lambda row: "4625" in str(row).lower(), axis=1)]

                        # Count failed attempts per user
                        if not failed_logins.empty:
                            if "Account Name" in failed_logins.columns:
                                user_col = "Account Name"
                            elif "TargetUserName" in failed_logins.columns:
                                user_col = "TargetUserName"
                            else:
                                user_col = failed_logins.columns[0]  # fallback

                            failed_logins[user_col] = failed_logins[user_col].astype(str).str.strip()
                            failed_counts = failed_logins[user_col].value_counts()
                            st.subheader("Failed Login Attempts per User")
                            st.write(failed_counts)
                            threshold = 1
 
                            # st.write("DEBUG: Threshold =", threshold)
                            st.write("DEBUG: Suspicious users (should be >= threshold):")
                            st.write(failed_counts[failed_counts >= threshold])

                            suspicious_users = failed_counts[failed_counts >= threshold]
                            if not suspicious_users.empty:
                                st.error("Suspicious activity detected! Users with many failed logins:")
                                for user, count in suspicious_users.items():
                                    st.write(f"- {user}: {count} failed attempts")
                            else:
                                st.success("No suspicious failed login activity detected.")
                        else:
                            st.info("No failed login attempts found in this log.")
                    else:
                        st.info("Log analysis for this log type is not implemented yet.")
                except Exception as e:
                    st.error(f"Error analyzing log: {e}")

with tab3:
    st.header("Memory Analysis")
    uploaded_memory = st.file_uploader("Upload a memory dump file", type=["dmp", "raw", "bin", "mem", "txt"], key="memory_uploader")
    
    if uploaded_memory is not None:
        # Save the uploaded memory dump temporarily
        temp_mem_path = os.path.join("temp", uploaded_memory.name)
        os.makedirs("temp", exist_ok=True)
        
        with open(temp_mem_path, "wb") as f:
            f.write(uploaded_memory.getbuffer())
        
        if st.button("Analyze Memory Dump"):
            with st.spinner("Analyzing memory dump..."):
                try:
                    # Import memory analyzer if not already imported
                    from engine.memory_analyzer import analyze_memory_dump
                    
                    # Analyze memory dump
                    results = analyze_memory_dump(temp_mem_path)
                    
                    if "error" in results:
                        st.error(f"Error in analysis: {results['error']}")
                    else:
                        # Display results in tabs
                        mem_tab1, mem_tab2, mem_tab3 = st.tabs(["Processes", "Network Connections", "Suspicious Activity"])
                        
                        # Processes tab
                        with mem_tab1:
                            st.subheader(f"Processes ({results['process_count']})")
                            if results['processes']:
                                process_df = pd.DataFrame(results['processes'])
                                st.dataframe(process_df)
                            else:
                                st.write("No processes found in memory dump")
                        
                        # Network connections tab
                        with mem_tab2:
                            st.subheader(f"Network Connections ({results['connection_count']})")
                            if results['network_connections']:
                                conn_df = pd.DataFrame(results['network_connections'])
                                st.dataframe(conn_df)
                            else:
                                st.write("No network connections found in memory dump")
                        
                        # Suspicious activity tab
                        with mem_tab3:
                            st.subheader("Suspicious Processes")
                            if results['suspicious_processes']:
                                for proc in results['suspicious_processes']:
                                    st.error(f"**{proc['process']}** (PID: {proc['pid']}): {proc['reason']}")
                            else:
                                st.success("No suspicious processes detected")
                            
                except Exception as e:
                    st.error(f"Error analyzing memory dump: {e}")

with tab4:
    st.header("Timeline Analysis")
    st.write("Create a chronological timeline by adding multiple evidence sources")
    
    # Create a container for file upload controls
    with st.container():
        st.subheader("Add Evidence Sources")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            timeline_file = st.file_uploader("Upload evidence file", key="timeline_uploader")
        
        with col2:
            source_type = st.selectbox("Source type", ["log", "memory", "file"])
        
        with col3:
            if source_type == "log":
                subtype = st.selectbox("Log type", ["windows", "apache", "ssh", "generic"])
            else:
                subtype = "N/A"
        
        # Session state to store timeline sources
        if 'timeline_sources' not in st.session_state:
            st.session_state.timeline_sources = []
        
        # Button to add source
        if st.button("Add to Timeline"):
            if timeline_file:
                temp_path = os.path.join("temp", timeline_file.name)
                os.makedirs("temp", exist_ok=True)
                
                with open(temp_path, "wb") as f:
                    f.write(timeline_file.getbuffer())
                
                # Add to sources list
                source = {
                    "path": temp_path,
                    "type": source_type,
                    "description": timeline_file.name
                }
                
                if source_type == "log":
                    source["log_type"] = subtype
                
                st.session_state.timeline_sources.append(source)
                st.success(f"Added {timeline_file.name} to timeline sources")
    
    # Display current sources
    if st.session_state.timeline_sources:
        st.subheader("Current Sources")
        for i, source in enumerate(st.session_state.timeline_sources):
            st.write(f"{i+1}. **{source['description']}** (Type: {source['type']})")
        
        # Clear button
        if st.button("Clear All Sources"):
            st.session_state.timeline_sources = []
            st.info("Timeline sources cleared")
        
        # Generate timeline button
        if st.button("Generate Timeline"):
            with st.spinner("Generating timeline..."):
                try:
                    # Import timeline analyzer
                    from engine.timeline_analyzer import create_event_timeline, detect_timeline_anomalies
                    
                    # Create timeline
                    timeline_df = create_event_timeline(st.session_state.timeline_sources)
                    
                    # Detect anomalies
                    anomalies = detect_timeline_anomalies(timeline_df)
                    
                    # Display timeline
                    st.subheader(f"Event Timeline ({len(timeline_df)} events)")
                    
                    if not timeline_df.empty:
                        # Sort by timestamp
                        timeline_df = timeline_df.sort_values('timestamp')
                        
                        # Display as dataframe
                        st.dataframe(timeline_df)
                        
                        # Create visualization
                        st.subheader("Timeline Visualization")
                        
                        try:
                            # Convert to datetime if not already
                            if not pd.api.types.is_datetime64_dtype(timeline_df['timestamp']):
                                timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
                            
                            # Ensure event_type exists, use source if not
                            if 'event_type' not in timeline_df.columns:
                                timeline_df['event_type'] = timeline_df['source']
                            
                            # Group by timeframe - use any column that definitely exists
                            column_to_count = 'event_type' if 'event_type' in timeline_df.columns else 'source'
                            timeline_counts = timeline_df.resample('h', on='timestamp').count()[column_to_count]
                            
                            # Plot
                            fig, ax = plt.subplots(figsize=(10, 5))
                            timeline_counts.plot(kind='bar', ax=ax)
                            plt.title('Events Over Time')
                            plt.xlabel('Time')
                            plt.ylabel('Number of Events')
                            st.pyplot(fig)
                        except Exception as e:
                            st.error(f"Error in timeline visualization: {str(e)}")
                            st.write("Displaying raw timeline data instead:")
                            st.dataframe(timeline_df)
                        
                        # Display anomalies
                        st.subheader("Detected Anomalies")
                        if anomalies:
                            for anomaly in anomalies:
                                st.error(f"**{anomaly['type']}** at {anomaly['timestamp']}: {anomaly.get('description', '')}")
                        else:
                            st.success("No anomalies detected in timeline")
                        
                        # Export options
                        export_format = st.selectbox("Export format", ["csv", "json"])
                        if st.button("Export Timeline"):
                            # Create export path
                            export_path = os.path.join("temp", f"timeline_export.{export_format}")
                            
                            from engine.timeline_analyzer import export_timeline
                            if export_timeline(timeline_df, export_path, format=export_format):
                                st.success(f"Timeline exported to {export_path}")
                    else:
                        st.warning("No events found in the timeline")
                    
                except Exception as e:
                    st.error(f"Error generating timeline: {e}")
    else:
        st.info("Add evidence sources to generate a timeline")
