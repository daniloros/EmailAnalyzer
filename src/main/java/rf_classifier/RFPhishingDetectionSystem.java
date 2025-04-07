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
        System.out.println("Addestramento del classificatore...");
        classifier.train(embeddings, labels);

        // Valuta le performance
        System.out.println("\nValutazione del modello...");
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

    public void analyzeEmailWithFeedback(String emailText, PhishingResult result, boolean userFeedback) throws Exception {
        // Prima facciamo l'analisi normale

        // Creiamo un oggetto feedback
        ProcessedEmailForJSON feedback = new ProcessedEmailForJSON(
                emailText,
                userFeedback,
                result.getEmbedding(),
                result.getNum_token(),
                new Date()
        );

        // Salviamo il feedback in un file JSON
        saveFeedbackToJson(feedback);
    }

    private void saveFeedbackToJson(ProcessedEmailForJSON feedback) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        File feedbackFile = new File(datasetPath + "/feedback_dataset.json");

        List<ProcessedEmailForJSON> existingFeedback = new ArrayList<>();

        // Se il file esiste, leggiamo il contenuto esistente
        if (feedbackFile.exists()) {
            existingFeedback = mapper.readValue(feedbackFile,
                    mapper.getTypeFactory().constructCollectionType(List.class, ProcessedEmailForJSON.class));
        }

        // Aggiungiamo il nuovo feedback
        existingFeedback.add(feedback);

        // Salviamo il file aggiornato
        mapper.writeValue(feedbackFile, existingFeedback);
    }

    public static void main(String[] args) {
        try {
            // Configurazione del sistema
            String umbertoApiUrl = "http://localhost:8000/analyze";
            String datasetPath = "dataset/processed";

            // Crea le directory necessarie
            Files.createDirectories(Paths.get(datasetPath));

            // Inizializza il sistema
            RFPhishingDetectionSystem system = new RFPhishingDetectionSystem(datasetPath);

            // carico il modello
            system.loadModel("rf_model_test_new.model");
//           // Salva il modello addestrato
//            system.saveModel("phishing_model.model");

            // Esempio di analisi di una nuova email
            String emailText = "Inserisci un testo mail di prova ...";
            PhishingResult result = system.analyzeEmail(emailText, null);

            System.out.println("\nRisultato analisi:");
            System.out.println("Email: " + result.getEmailText());
            System.out.println("È phishing? " + result.isPhishing());

            // Chiediamo il feedback all'utente
            System.out.println("\nQuesta predizione è corretta? (s/n):");
            Scanner scanner = new Scanner(System.in);
            String userInput = scanner.nextLine().toLowerCase();

            boolean actualPhishing = result.isPhishing(); // valore predetto di default
            if (userInput.equals("n")) {
                // Se l'utente dice che la predizione è sbagliata, invertiamo il valore
                actualPhishing = !result.isPhishing();
            }

            System.out.println("Attendi... creo il file json");
            system.analyzeEmailWithFeedback(emailText ,result, actualPhishing);

            System.out.println("\nFeedback salvato correttamente!");

            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

