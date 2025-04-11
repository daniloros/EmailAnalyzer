package svm_classifier;

import controller.*;
import model.EmailFromBert;
import model.MailData;
import model.PhishingResult;

import java.util.List;

/**
 * This class implements a phishing detection system based on SVM.
 * It uses BERT embeddings with a Support Vector Machine (SVM) classifier.
 * The SVM is particularly effective with our data because:
 * 1. It handles high-dimensional spaces well (768D of BERT embeddings)
 * 2. It is robust with small-sized datasets
 * 3. It can be optimized to handle class imbalance
 *       we can give more weight to Italian emails
 */

public class SVMPhishingDetectionSystem {
    private final SVMPhishingClassifier classifier;
    private final String datasetPath;

    public SVMPhishingDetectionSystem(String datasetPath) {
        this.classifier = new SVMPhishingClassifier();
        this.datasetPath = datasetPath;
    }

    /**
     * Analyzes a single email using the SVM classifier.
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


        // classify using SVM
        boolean isPhishing = classifier.classify(combinedFeature);

        return new PhishingResult(emailText, isPhishing, combinedFeature, emailFromBert.getNum_tokens());
    }


    /**
     * Load a previously saved SVM model
     */
    public void loadModel(String filepath) throws Exception {
        classifier.loadModel(filepath);
    }


}
