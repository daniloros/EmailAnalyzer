package rf_classifier;

import controller.*;
import model.EmailFromBert;
import model.MailData;
import model.PhishingResult;

import java.util.List;

/**
 * This class integrates the Bert service with the phishing classifier.
 * It handles the entire email analysis process, from obtaining the
 * embeddings to the final classification.
 */
public class RFPhishingDetectionSystem {
    private final RFPhishingClassifier classifier;
    private final String datasetPath;

    public RFPhishingDetectionSystem(String datasetPath) {
        this.classifier = new RFPhishingClassifier();
        this.datasetPath = datasetPath;
    }

    /**
     * Analyzes a single email and determines if it is phishing
     */

    public PhishingResult analyzeEmail(String emailText, List<String> extractedUrls) throws Exception {
        // Gets the embedding from BERT
        MailData mailData = new MailData();
        EmailFromBert emailFromBert = BERTEmbeddingClient.getEmbedding(emailText);
        float[] embedding = emailFromBert.getEmbedding();

        NaturalLanguage.extractNaturalLanguage(mailData, emailText);

        EmailLinkExtractor featureExtractor = new EmailLinkExtractor(emailText);
        featureExtractor.extractLinkFeatures(mailData, extractedUrls);

        SpamDetectorFromJson spamDetectorFromJson = new SpamDetectorFromJson(emailText);
        spamDetectorFromJson.findSpamWord(mailData);

        float[] combinedFeature = FeatureConverter.combineFeatures(embedding, mailData);


        // Classify the embedding
        boolean isPhishing = classifier.classify(combinedFeature);

        return new PhishingResult(emailText, isPhishing, combinedFeature, emailFromBert.getNum_tokens());
    }


    /**
     * Loads a previously saved model
     */
    public void loadModel(String filepath) throws Exception {
        classifier.loadModel(filepath);
    }

}

