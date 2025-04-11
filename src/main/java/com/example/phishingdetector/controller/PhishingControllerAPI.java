package com.example.phishingdetector.controller;

import com.example.phishingdetector.dto.ComparisonResponse;
import com.example.phishingdetector.dto.EmailRequest;
import com.example.phishingdetector.dto.EmailResponse;
import com.example.phishingdetector.dto.FeedbackRequest;
import com.example.phishingdetector.service.EmailParserService;
import com.example.phishingdetector.service.PhishingDetectionService;
import model.PhishingResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class PhishingControllerAPI {
    private static final Logger logger = LoggerFactory.getLogger(PhishingControllerAPI.class);

    @Autowired
    private PhishingDetectionService detectionService;

    @Autowired
    private EmailParserService emailParserService;

    private Map<String, PhishingResult> resultCache = new HashMap<>();

    @PostMapping("/analyze/rf")
    public ResponseEntity<EmailResponse> analyzeWithRandomForest(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithRandomForest(request.getText(), request.getExtractedUrls());
            String key = "rf-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "Random Forest",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error while parsing with Random Forest", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/svm")
    public ResponseEntity<EmailResponse> analyzeWithSVM(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithSVM(request.getText(), request.getExtractedUrls());
            String key = "svm-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "SVM",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error while parsing with SVM", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/xgboost")
    public ResponseEntity<EmailResponse> analyzeWithXGBoost(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithXGBoost(request.getText(), request.getExtractedUrls());
            String key = "xgboost-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "XGBoost",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error while parsing with XGBoost", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/compare")
    public ResponseEntity<ComparisonResponse> compareClassifiers(@RequestBody EmailRequest request) {
        try {
            PhishingResult rfResult = detectionService.analyzeWithRandomForest(request.getText(), request.getExtractedUrls());
            PhishingResult svmResult = detectionService.analyzeWithSVM(request.getText(), request.getExtractedUrls());
            PhishingResult xgboostResult = detectionService.analyzeWithXGBoost(request.getText(), request.getExtractedUrls());

            // Save results in cache
            String rfKey = "rf-" + System.currentTimeMillis();
            String svmKey = "svm-" + System.currentTimeMillis();
            String xgbKey = "xgboost-" + System.currentTimeMillis();

            resultCache.put(rfKey, rfResult);
            resultCache.put(svmKey, svmResult);
            resultCache.put(xgbKey, xgboostResult);

            ComparisonResponse response = new ComparisonResponse(
                    rfResult.isPhishing(),
                    svmResult.isPhishing(),
                    xgboostResult.isPhishing(),
                    request.getText(),
                    rfResult.getNum_token(),
                    rfKey,
                    svmKey,
                    xgbKey
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error comparing classifiers", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/feedback")
    public ResponseEntity<?> saveFeedback(@RequestBody FeedbackRequest request) {
        try {
            logger.info("Feedback request received: {}", request);

            // Verifichiamo se abbiamo questo risultato nella cache
            PhishingResult cachedResult = null;
            if (request.getResultId() != null && !request.getResultId().isEmpty()) {
                cachedResult = resultCache.get(request.getResultId());
            }

            if (cachedResult != null) {
                logger.info("Found result in cache with ID: {}", request.getResultId());

                detectionService.saveFeedback(
                        cachedResult.getEmailText(),
                        request.isUserFeedback(),
                        cachedResult.getEmbedding(),
                        cachedResult.getNum_token(),
                        request.getClassifier()
                );
            } else {
                // If don't have the result in cache, we proceed anyway but re-analyzing the email
                logger.warn("Result not found in cache, re-analyzing email");

                // reanalyze the email to get all the necessary data
                PhishingResult freshResult = null;
                String classifier = request.getClassifier().toLowerCase();

                if (classifier.contains("rf") || classifier.contains("random")) {
                    freshResult = detectionService.analyzeWithRandomForest(request.getEmailText(),null);
                } else if (classifier.contains("svm")) {
                    freshResult = detectionService.analyzeWithSVM(request.getEmailText(), null);
                } else if (classifier.contains("xgboost")) {
                    freshResult = detectionService.analyzeWithXGBoost(request.getEmailText(), null);
                } else {
                    // Default a Random Forest se il classificatore non è specificato correttamente
                    freshResult = detectionService.analyzeWithRandomForest(request.getEmailText(), null);
                }

                detectionService.saveFeedback(
                        freshResult.getEmailText(),
                        request.isUserFeedback(),
                        freshResult.getEmbedding(),
                        freshResult.getNum_token(),
                        request.getClassifier()
                );
            }

            return ResponseEntity.ok().body(Map.of("status", "success", "message", "Feedback saved successfully"));
        } catch (Exception e) {
            logger.error("Error saving feedback", e);
            return ResponseEntity.internalServerError().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }


    public PhishingResult getResultFromCache(String resultId) {
        return resultCache.get(resultId);
    }

    private String summarizeFeatures(float[] embedding) {
        // return only some values
        if (embedding.length > 5) {
            return "Size: " + embedding.length + ", First value: " +
                    Arrays.toString(Arrays.copyOfRange(embedding, 0, 5)) + "...";
        } else {
            return "Size: " + embedding.length + ", Value: " + Arrays.toString(embedding);
        }
    }
}