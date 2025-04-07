package controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import model.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Centralized class for extracting and processing email features.
 * This class processes emails once and creates a single dataset for all classifiers.
 */
public class EmailFeatureProcessor {
    private final String datasetPath;

    public EmailFeatureProcessor(String datasetPath) {
        this.datasetPath = datasetPath;
    }

    /**
     * Processes all emails in the input JSON file and extracts features.
     * Creates a unified processed dataset that can be used by all classifiers.
     *
     * @param inputJsonPath Path to the original JSON file with email data
     * @return Path to the processed dataset file
     */
    public String processEmails(String inputJsonPath, String outputFileName) throws Exception {
        // Ensure output directory exists
        Files.createDirectories(Paths.get(datasetPath));

        // Output file path
        String outputFilePath = datasetPath + outputFileName;

        ObjectMapper mapper = new ObjectMapper();
        List<ProcessedEmailForJSON> processedEmails = new ArrayList<>();

        // Read the input JSON
        JsonNode root = mapper.readTree(new File(inputJsonPath));
        JsonNode emails = root.get("emails");

        // Process each email
        for (JsonNode emailNode : emails) {
            try {
                String text = emailNode.get("text").asText();
                boolean isPhishing = emailNode.get("type").asText().toLowerCase().contains("phishing");
                float sentimentMagnitude = Float.parseFloat(emailNode.get("metadata").get("sentiment_magnitude").asText());
                float sentimentScore = Float.parseFloat(emailNode.get("metadata").get("sentiment_score").asText());

                // Create a MailData object to hold extracted features
                MailData mailData = new MailData();
                mailData.setSentimentMagnitude(sentimentMagnitude);
                mailData.setSentimentScore(sentimentScore);

                // Get BERT embedding
                EmailFromBert emailFromBert = BERTEmbeddingClient.getEmbedding(text);
                float[] embedding = emailFromBert.getEmbedding();

                // Extract link features
                EmailLinkExtractor featureExtractor = new EmailLinkExtractor(text);
                featureExtractor.extractLinkFeatures(mailData, null);

                // Extract spam words
                SpamDetectorFromJson spamDetector = new SpamDetectorFromJson(text);
                spamDetector.findSpamWord(mailData);

                // Combine all features
                float[] combinedFeatures = FeatureConverter.combineFeatures(embedding, mailData);

                // Create a processed email object
                ProcessedEmailForJSON processedEmail = new ProcessedEmailForJSON(
                        text,
                        isPhishing,
                        combinedFeatures,
                        emailFromBert.getNum_tokens(),
                        new Date()
                );

                processedEmails.add(processedEmail);

            } catch (Exception e) {
                System.err.println("Error processing email: " + e.getMessage());
                e.printStackTrace();
            }
        }

        // Save the processed emails to a single file
        mapper.writeValue(new File(outputFilePath), processedEmails);

        return outputFilePath;
    }

    /**
     * Loads processed emails from the unified dataset file.
     *
     * @return List of processed emails with features
     */
    public List<ProcessedEmailForJSON> loadProcessedEmails(String outputFileName) throws IOException {
        String filePath = datasetPath + outputFileName;
        ObjectMapper mapper = new ObjectMapper();

        return mapper.readValue(
                new File(filePath),
                mapper.getTypeFactory().constructCollectionType(List.class, ProcessedEmailForJSON.class)
        );
    }
}