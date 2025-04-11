package xgboost_classifier;

import controller.*;
import model.EmailFromBert;
import model.MailData;
import model.PhishingResult;

import java.util.List;

/**
 * This class integrates the BERT service with the XGBoost phishing classifier.
 * It is based on the RFPhishingDetectionSystem class but uses XGBoost instead of Random Forest.
 */

public class XGBoostPhishingDetectionSystem {
    private final XGBoostPhishingClassifier classifier;
    private final String datasetPath;

    public XGBoostPhishingDetectionSystem(String datasetPath) {
        this.classifier = new XGBoostPhishingClassifier();
        this.datasetPath = datasetPath;
    }

    /**
     * Analyzes a single email and determines if it is phishing
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
     * Loads a previously saved model
     */
    public void loadModel(String filepath) throws Exception {
        classifier.loadModel(filepath);
    }


}