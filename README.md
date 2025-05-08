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

# Setup and Installation

### Prerequisites 
- Java 17 or higher
- Maven
- Google Cloud Account (for Natural Language API and Storage)
- Gemini API key

### Configuration
1. Set the required environment variables:
```
app.spam.words.it=path/to/italian/spam/words.json
app.spam.words.en=path/to/english/spam/words.json
app.bert.api.url=your-bert-service-url
app.dataset.path=path/to/datasets
app.model.rf.path=path/to/rf_model.model
app.model.svm.path=path/to/svm_model.model  
app.model.xgboost.path=path/to/xgboost_model.model
app.cloud.storage.name=your-cloud-storage-bucket-name
app.gemini.api.key=your-gemini-api-key
GEMINI_API_KEY=your-gemini-api-key
```
2. Build the project
3. Run the application

# Using the System
### Web Interface
Access the web interface at http://localhost:8080
1. Email Analyzer: Upload an email (.eml file) or paste email content. Analyze it with specific classifier
2. Comparison Tool: Upload an email (.eml file) or paste email content. Analyze and Compare results from all tre classifier
3. Gemini Analysis: Get detailed explanations of classification results

## REST API
**Analyze with a speciic classifier:**
```
POST /api/analyze/rf
POST /api/analyze/svm
POST /api/analyze/xgboost
```
Request body:
```
{
  "text": "Email content goes here",
  "extractedUrls": ["http://example.com", "http://suspicious.link"]
}
```
**Compare all classifiers:**
```
POST /api/analyze/compare
```
**Get Gemini analysis:**
```
POST /api/gemini/analyze
```
**Provide feedback:**
```
POST /api/feedback
```

# Training and Evaluation
The system includes components for training and evaluating the models:

**1. Training:**
```
TrainingModels.java
```
This trains all three models on the same dataset of processed emails.

**2. Evaluation:**
```
TestDataEvaluation.java
```
This evaluates the performance of the trained models on a validation dataset.

**3. Gemini Concordance Analysis:**
```
GeminiConcordanceAnalysis.java
```
This analyzes how well Gemini's classifications align with the machine learning models
