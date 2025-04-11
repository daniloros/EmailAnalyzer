package com.example.phishingdetector.controller;

import com.example.phishingdetector.service.EmailParserService;
import com.example.phishingdetector.service.GeminiService;
import model.PhishingResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@RestController
@RequestMapping("/api/gemini")
public class GeminiControllerAPI {
    private static final Logger logger = LoggerFactory.getLogger(GeminiControllerAPI.class);

    @Autowired
    private GeminiService geminiService;

    @Autowired
    private EmailParserService emailParserService;

    @Autowired
    private PhishingControllerAPI phishingControllerAPI;

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeWithGemini(@RequestBody Map<String, Object> request) {
        try {
            // create request
            String emailContent = (String) request.get("emailText");
            Boolean classification = (Boolean) request.get("classification");
            String classifier = (String) request.get("classifier");

            String resultId = request.containsKey("resultId") ? (String) request.get("resultId") : null;



            if (emailContent == null || classification == null || classifier == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "emailText, classification e classifier are mandatory"
                ));
            }

            float[] embedding = null;
            if (resultId != null && !resultId.isEmpty()) {
                // Cache for result of PhishingControllerAPI
                PhishingResult cachedResult = phishingControllerAPI.getResultFromCache(resultId);
                if (cachedResult != null) {
                    embedding = cachedResult.getEmbedding();
                    logger.info("Dimension of embedding {} from resultId {}",
                            embedding != null ? embedding.length : 0, resultId);
                }
            }


            // Get list of URLs from request if provided
            List<String> providedUrls = null;
            if (request.containsKey("urls") && request.get("urls") instanceof List) {
                providedUrls = (List<String>) request.get("urls");
            }

            // Use the URLs provided or extract them from the text
            List<String> urls;
            if (providedUrls != null && !providedUrls.isEmpty()) {
                urls = providedUrls;
                logger.info("Using {} URLs provided directly from the request", urls.size());
            } else {
                urls = emailParserService.extractUrlsFromText(emailContent);
                logger.info("Extract {} URL from email text", urls.size());
            }

            logger.info("Gemini Analysis Request for Email Classified as {} from {}",
                    classification ? "PHISHING" : "LEGIT", classifier);

            // Chiamata asincrona a Gemini
            CompletableFuture<String> geminiAnalysisFuture = geminiService.analyzeEmailWithGemini(
                    emailContent,
                    urls,
                    classification,
                    classifier,
                    embedding
            );

            // Attendiamo la risposta di Gemini con un timeout
            String geminiAnalysis = geminiAnalysisFuture.get(15, TimeUnit.SECONDS);

            logger.info("Gemini analysis completed");

            return ResponseEntity.ok().body(Map.of(
                    "status", "success",
                    "analysis", geminiAnalysis
            ));

        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            logger.warn("Problem getting analysis from Gemini", e);
            return ResponseEntity.ok().body(Map.of(
                    "status", "error",
                    "message", "Could not get analysis from Gemini: " + e.getMessage()
            ));
        } catch (ClassCastException e) {
            logger.error("Format error in request parameters", e);
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Parameter format error: URLs must be a list of stringse"
            ));
        } catch (Exception e) {
            logger.error("Error while parsing with Gemini", e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Error while parsing: " + e.getMessage()
            ));
        }
    }
}