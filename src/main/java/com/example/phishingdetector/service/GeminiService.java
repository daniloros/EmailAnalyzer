package com.example.phishingdetector.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Service
public class GeminiService {
    private static final Logger logger = LoggerFactory.getLogger(GeminiService.class);
    private static final String GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-thinking-exp-01-21:generateContent";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient;

    @Value("${app.gemini.api.key}")
    private String apiKeyFromProperties;

    private String apiKey;

    public GeminiService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @PostConstruct
    public void init() {
        // Try reading directly from the environment variable first
        String envApiKey = System.getenv("GEMINI_API_KEY");

        //If available from the environment variable, use that
        if (envApiKey != null && !envApiKey.isEmpty()) {
            this.apiKey = envApiKey;
            logger.info("Using Gemini API key from environment variable");
        }
        // Otherwise use the one from the Spring properties
        else if (apiKeyFromProperties != null && !apiKeyFromProperties.isEmpty()) {
            this.apiKey = apiKeyFromProperties;
            logger.info("Using Gemini API Keys from Spring Properties");
        }
        // If not available, warning log
        else {
            logger.warn("No Gemini API key found! API requests will fail");
        }
    }

    /**
     * Analyzes the email classification results along with the links found
     *
     * @param emailContent Content of the analyzed email
     * @param urls List of URLs found in the email
     * @param classification Classification result (true = phishing, false = legitimate)
     * @param classifier Name of the classifier used (RF, SVM, XGBoost)
     * @return CompletableFuture containing the Gemini analysis as a string
     */

    public CompletableFuture<String> analyzeEmailWithGemini(String emailContent, List<String> urls,
                                                            boolean classification, String classifier, float[] embedding) {
        try {
            if (apiKey == null || apiKey.isEmpty()) {
                CompletableFuture<String> future = new CompletableFuture<>();
                future.complete("Error: Gemini API key not configureda");
                return future;
            }

            String prompt = buildPrompt(emailContent, urls, classification, classifier, embedding);

            logger.debug("PROMPT SENT TO GEMINI:\n{}", prompt);


            //Builds JSON payload for Gemini API
            ObjectNode contentNode = objectMapper.createObjectNode();
            contentNode.put("role", "user");
            contentNode.put("parts", objectMapper.createArrayNode().add(
                    objectMapper.createObjectNode().put("text", prompt)
            ));

            ObjectNode requestBody = objectMapper.createObjectNode();
            ArrayNode contentsArray = objectMapper.createArrayNode();
            contentsArray.add(contentNode);
            requestBody.set("contents", contentsArray);


            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GEMINI_API_ENDPOINT + "?key=" + apiKey))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                    .build();

            return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenApply(response -> {
                        if (response.statusCode() == 200) {
                            try {
                                JsonNode responseJson = objectMapper.readTree(response.body());
                                return extractGeminiResponse(responseJson);
                            } catch (Exception e) {
                                logger.error("Error parsing Gemini response", e);
                                return "EError processing response: " + e.getMessage();
                            }
                        } else {
                            logger.error("Error calling Gemini API: " + response.statusCode() + " - " + response.body());
                            return "Error calling Gemini: " + response.statusCode();
                        }
                    })
                    .exceptionally(ex -> {
                        logger.error("Exception while calling Gemini API", ex);
                        return "Connection error: " + ex.getMessage();
                    });
        } catch (Exception e) {
            logger.error("Error preparing request to Gemini", e);
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Builds the prompt to send to Gemini
     */

    private String buildPrompt(String emailContent, List<String> urls, boolean classification,
                              String classifier, float[] embedding) {
        StringBuilder prompt = new StringBuilder();

        // Introduction and context
        prompt.append("Imagine you are a cybersecurity expert who has to classify an email as phishing or legitimate.");
        prompt.append("The email has already been classified as");
        prompt.append(classification ? "PHISHING" : "LEGIT");
        prompt.append(" from the ").append(classifier).append("classifier, ");
        prompt.append("but you should not be influenced by this classification because the classifier has a margin of error.\n\n");

        // Content of the Email
        prompt.append("CONTENT OF THE EMAIL:\n").append(emailContent).append("\n\n");

        // URLs found
        prompt.append("URLS FOUND IN THE EMAIL:\n");
        if (urls != null && !urls.isEmpty()) {
            for (String url : urls) {
                prompt.append("- ").append(url).append("\n");
            }
        } else {
            prompt.append("No URLs found.\n");
        }
        prompt.append("\n");

        // Technical information about embeddings and features
        if (embedding != null && embedding.length > 0) {
            prompt.append("TECHNICAL INFORMATION:\n");
            prompt.append("The email was analyzed with multilingual BERT embedding. ");


            if (embedding.length >= 774) {  //768 from BERT embedding + 6 additional features
                int embeddingSize = embedding.length - 6;

                prompt.append("The embedding is a vector of").append(embedding.length).append(" elements. ");
                prompt.append("The first ").append(embeddingSize).append(" elements are the BERT embedding values, ");
                prompt.append("while the last 6 elements are specific features:\n\n");

                // Special feature values
                float containsUrl = embedding[embeddingSize];
                float containsIpUrl = embedding[embeddingSize + 1];
                float containsNonAscii = embedding[embeddingSize + 2];
                float containsSpamWords = embedding[embeddingSize + 3];
                float sentimentScore = embedding[embeddingSize + 4];
                float sentimentMagnitude = embedding[embeddingSize + 5];

                prompt.append("1. Presence of URLs: ").append(containsUrl > 0.5 ? "Yes" : "No").append(" (").append(String.format("%.2f", containsUrl)).append(")\n");
                prompt.append("2. Presence of URLs with IP addresses:").append(containsIpUrl > 0.5 ? "Yes" : "No").append(" (").append(String.format("%.2f", containsIpUrl)).append(")\n");
                prompt.append("3. Presence of URLs with non-ASCII characters: ").append(containsNonAscii > 0.5 ? "Yes" : "No").append(" (").append(String.format("%.2f", containsNonAscii)).append(")\n");
                prompt.append("4. Presence of typical spam words:").append(containsSpamWords > 0.5 ? "Yes" : "No").append(" (").append(String.format("%.2f", containsSpamWords)).append(")\n");
                prompt.append("5. Sentiment score (Natural Language API): ").append(String.format("%.4f", sentimentScore));
                prompt.append("6. Sentiment magnitude (Natural Language API): ").append(String.format("%.4f", sentimentMagnitude));
            } else {
                // If for some reason the embedding does not have the expected features
                prompt.append("The embedding has a size of").append(embedding.length).append(" elements.\n\n");
            }
        }

        // Request for analysis
        prompt.append("REQUEST:\n");
        prompt.append("Provide a detailed analysis of up to 300 words to this email, considering all the elements provided. Your analysis should include:\n");
        prompt.append("1. Whether or not you agree with the initial classification and why\n");
        prompt.append("2. Suspicious elements or phishing indicators present in the text\n");
        prompt.append("3. URL analysis (if any): are they legitimate or suspicious?\n");
        prompt.append("4. Considerations on the extracted technical features\n");
        prompt.append("5. Final conclusion: do you classify this email as PHISHING or LEGITIMATE?\n\n");
        prompt.append("Respond in a structured format with headings for each section of your analysis. Keep the analysis concise but complete.");

        return prompt.toString();
    }

    /**
     * Extracts the response text from the JSON returned by Gemini
     */

    private String extractGeminiResponse(JsonNode responseJson) {
        try {
            // Navigate through the JSON to extract the response text
            JsonNode candidates = responseJson.path("candidates");
            if (candidates.isArray() && candidates.size() > 0) {
                JsonNode content = candidates.get(0).path("content");
                JsonNode parts = content.path("parts");
                if (parts.isArray() && parts.size() > 0) {
                    return parts.get(0).path("text").asText();
                }
            }
            return "No response generated by Gemini";
        } catch (Exception e) {
            logger.error("Error extracting Gemini response", e);
            return "Error processing response: " + e.getMessage();
        }
    }
}