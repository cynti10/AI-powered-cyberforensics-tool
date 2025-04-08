import streamlit as st
from engine.feature_extractor import extract_features
from engine.model_predictor import predict_malware
from utils.hash_utils import compute_hashes
from engine.yara_scanner import run_yara_scan
from engine.report_generator import generate_report

st.title("AI-Powered Cyberforensics Tool")

uploaded_file = st.file_uploader("Upload a file to analyze")

if uploaded_file:
    filepath = f"data/samples/{uploaded_file.name}"
    with open(filepath, "wb") as f:
        f.write(uploaded_file.read())

    features = extract_features(filepath)
    prediction = predict_malware(features)
    hashes = compute_hashes(filepath)
    yara_results = run_yara_scan(filepath)

    st.subheader("Prediction")
    st.write(prediction)

    st.subheader("Features")
    st.json(features)

    st.subheader("Hashes")
    st.json(hashes)

    st.subheader("YARA Matches")
    st.json(yara_results)

    generate_report(filepath, features, prediction, hashes, yara_results)
    st.success("Report generated successfully!")
