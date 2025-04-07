package rf_classifier;

import controller.*;
import model.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.io.*;
import java.nio.file.*;

/**
 * Questa classe integra il servizio UmBERTO con il classificatore di phishing.
 * Gestisce l'intero processo di analisi delle email, dall'ottenimento degli
 * embedding fino alla classificazione finale.
 */
public class RFPhishingDetectionSystem {
    private final RFPhishingClassifier classifier;
    private final String datasetPath;

    public RFPhishingDetectionSystem(String datasetPath) {
        this.classifier = new RFPhishingClassifier();
        this.datasetPath = datasetPath;
    }

    /**
     * Analizza una singola email e determina se è phishing
     */
    public PhishingResult analyzeEmail(String emailText, List<String> extractedUrls) throws Exception {
        // Ottiene l'embedding da UmBERTO
        MailData mailData = new MailData();
        EmailFromBert emailFromBert = BERTEmbeddingClient.getEmbedding(emailText);
        float[] embedding = emailFromBert.getEmbedding();

        NaturalLanguage.extractNaturalLanguage(mailData, emailText);

        EmailLinkExtractor featureExtractor = new EmailLinkExtractor(emailText);
        featureExtractor.extractLinkFeatures(mailData, extractedUrls);

        SpamDetectorFromJson spamDetectorFromJson = new SpamDetectorFromJson(emailText);
        spamDetectorFromJson.findSpamWord(mailData);

        float[] combinedFeature = FeatureConverter.combineFeatures(embedding, mailData);


        // Classifica l'embedding
        boolean isPhishing = classifier.classify(combinedFeature);

        return new PhishingResult(emailText, isPhishing, combinedFeature, emailFromBert.getNum_tokens());
    }

    /**
     * Addestra il sistema usando un file di email etichettate
     */
    public void trainFromFile(String trainingDataFile) throws Exception {
        List<float[]> embeddings = new ArrayList<>();
        List<Boolean> labels = new ArrayList<>();
        List<ProcessedEmailForJSON> allProcessedEmails = new ArrayList<>();
        MailData mailData = new MailData();

        // Legge il file JSON delle email di training
        ObjectMapper mapper = new ObjectMapper();
        List<TrainingEmail> trainingEmails = mapper.readValue(
                new File(trainingDataFile),
                mapper.getTypeFactory().constructCollectionType(List.class, TrainingEmail.class)
        );


        // Per ogni email nel dataset
        for (TrainingEmail email : trainingEmails) {
            try {

                // Ottiene l'embedding
                EmailFromBert emailFromBert = BERTEmbeddingClient.getEmbedding(email.getText());
                float[] embedding = emailFromBert.getEmbedding();

                mailData.setSentimentMagnitude(email.getSentimentMagnitude());
                mailData.setSentimentScore(email.getSentimentScore());

                EmailLinkExtractor featureExtractor = new EmailLinkExtractor(email.getText());
                featureExtractor.extractLinkFeatures(mailData, null);

                SpamDetectorFromJson spamDetectorFromJson = new SpamDetectorFromJson(email.getText());
                spamDetectorFromJson.findSpamWord(mailData);

                float[] combinedFeature = FeatureConverter.combineFeatures(embedding, mailData);

                embeddings.add(combinedFeature);
                labels.add(email.isPhishing());

                // Salva l'embedding processato per uso futuro
                allProcessedEmails.add(new ProcessedEmailForJSON(
                        email.getText(),
                        email.isPhishing(),
                        combinedFeature,
                        emailFromBert.getNum_tokens(),
                        new Date()
                ));

            } catch (Exception e) {
                System.err.println("Errore nel processare l'email: " + e.getMessage());
            }
        }

        // Save all processed emails in a single file
        String filename = String.format("%s/rf_processed_emails.json", datasetPath);
        mapper.writeValue(new File(filename), allProcessedEmails);


        // Addestra il classificatore
        classifier.train(embeddings, labels);

        // Valuta le performance
        classifier.evaluate(embeddings, labels);
    }


    /**
     * Salva il modello addestrato
     */
    public void saveModel(String filepath) throws Exception {
        classifier.saveModel(filepath);
    }

    /**
     * Carica un modello precedentemente salvato
     */
    public void loadModel(String filepath) throws Exception {
        classifier.loadModel(filepath);
    }

}

