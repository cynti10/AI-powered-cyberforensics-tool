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
