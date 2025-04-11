package com.example.phishingdetector.dto;
public class FeedbackRequest {
    private String emailText;
    private boolean userFeedback;
    private String classifier;
    private String resultId; // ID for cache reference

    public FeedbackRequest() {
    }

    public FeedbackRequest(String emailText, boolean userFeedback, String classifier, String resultId) {
        this.emailText = emailText;
        this.userFeedback = userFeedback;
        this.classifier = classifier;
        this.resultId = resultId;
    }

    public String getEmailText() {
        return emailText;
    }

    public void setEmailText(String emailText) {
        this.emailText = emailText;
    }

    public boolean isUserFeedback() {
        return userFeedback;
    }

    public void setUserFeedback(boolean userFeedback) {
        this.userFeedback = userFeedback;
    }

    public String getClassifier() {
        return classifier;
    }

    public void setClassifier(String classifier) {
        this.classifier = classifier;
    }

    public String getResultId() {
        return resultId;
    }

    public void setResultId(String resultId) {
        this.resultId = resultId;
    }
}