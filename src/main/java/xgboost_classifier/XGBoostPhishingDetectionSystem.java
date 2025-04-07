package xgboost_classifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import controller.*;
import model.*;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Questa classe integra il servizio UmBERTO con il classificatore XGBoost per phishing.
 * È basata sulla classe RFPhishingDetectionSystem ma utilizza XGBoost invece di Random Forest.
 */
public class XGBoostPhishingDetectionSystem {
    private final XGBoostPhishingClassifier classifier;
    private final String datasetPath;

    public XGBoostPhishingDetectionSystem(String datasetPath) {
        this.classifier = new XGBoostPhishingClassifier();
        this.datasetPath = datasetPath;
    }

    /**
     * Analizza una singola email e determina se è phishing
     */
    public PhishingResult analyzeEmail(String emailText, List<String> extractedUrls) throws Exception {
        MailData mailData = new MailData();
        EmailFromBert emailFromBert = BERTEmbeddingClient.getEmbedding(emailText);
        float[] embedding = emailFromBert.getEmbedding();

        NaturalLanguage.extractNaturalLanguage(mailData, emailText);

        EmailLinkExtractor featureExtractor = new EmailLinkExtractor(emailText);
        featureExtractor.extractLinkFeatures(mailData, extractedUrls);

        SpamDetectorFromJson spamDetectorFromJson = new SpamDetectorFromJson(emailText);
        spamDetectorFromJson.findSpamWord(mailData);

        float[] combinedFeature = FeatureConverter.combineFeatures(embedding, mailData);

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

        System.out.println("Processando " + trainingEmails.size() + " email per il training...");

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

                // Combina embedding con altre feature
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

        // Salva tutte le email processate in un unico file
        String filename = String.format("%s/xgboost_processed_emails.json", datasetPath);
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