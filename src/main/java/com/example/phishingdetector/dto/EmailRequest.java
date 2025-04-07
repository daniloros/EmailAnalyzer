package com.example.phishingdetector.dto;

import java.util.List;

public class EmailRequest {
    private String text;
    private List<String> extractedUrls;

    public EmailRequest() {
    }

    public EmailRequest(String text) {
        this.text = text;
    }

    public EmailRequest(String text, List<String> extractedUrls) {
        this.text = text;
        this.extractedUrls = extractedUrls;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public List<String> getExtractedUrls() {
        return extractedUrls;
    }

    public void setExtractedUrls(List<String> extractedUrls) {
        this.extractedUrls = extractedUrls;
    }
}

