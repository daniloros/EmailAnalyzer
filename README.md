# PhishingDetector
A comprehensive phishing detection system that uses multiple machine learning models (Random Forest, SVM, and XGBoost) with BERT embeddings to identify phishing emails, enhanced with Google's Gemini LLM for advanced analysis and explanation.

# Project Overview
PhishingDetector is a Java-based application that integrates various machine learning algorithms with natural language processing to detect phishing attempts in emails. The system uses a hybrid approach combining BERT embeddings with additional features extracted from email content, achieving high accuracy in phishing detection. Additionally, it leverages Google's Gemini Large Language Model to provide expert-level analysis and human-readable explanations of the detection results, offering both machine learning precision and AI-powered insights.

# Key Features

- Multi-model Classification: Uses three different machine learning models for comparison:
  - Random Forest
  - Support Vector Machine (SVM)
  - XGBoost

- Advanced Feature Extraction:
  - BERT embeddings for semantic understanding
  - URL and link analysis
  - IP address detection in URLs
  - Non-ASCII character detection (potential homographic attacks)
  - Spam word detection
  - Sentiment analysis

- Web Interface and REST API:
  - Upload emails through web UI
  - Parse .eml files
  - Compare results across different classifiers
  - REST API for integration with other systems

- Gemini LLM Integration:
  - Secondary analysis using Google's Gemini model
  - Provides human-readable explanations of detection results

- User Feedback System:
  - Collects feedback to improve model accuracy
  - Stores feedback in cloud storage

- Comprehensive Evaluation:
  - Performance metrics for all models
  - Concordance analysis with Gemini LLM

# System Architecture
![system_sequence_diagram](https://github.com/user-attachments/assets/ff55e551-e501-4229-9b99-76768471d340)
