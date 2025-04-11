package com.example.phishingdetector.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.storage.*;
import model.PhishingResult;
import model.ProcessedEmailForJSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import rf_classifier.RFPhishingDetectionSystem;
import svm_classifier.SVMPhishingDetectionSystem;
import xgboost_classifier.XGBoostPhishingDetectionSystem;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class PhishingDetectionService {
    private static final Logger logger = LoggerFactory.getLogger(PhishingDetectionService.class);

    @Value("${app.dataset.path}")
    private String datasetPath;

    @Value("${app.model.rf.path}")
    private String rfModelPath;

    @Value("${app.model.svm.path}")
    private String svmModelPath;

    @Value("${app.model.xgboost.path}")
    private String xgboostModelPath;

    @Value("${app.cloud.storage.name}")
    private String bucketName;

    private RFPhishingDetectionSystem rfSystem;
    private SVMPhishingDetectionSystem svmSystem;
    private XGBoostPhishingDetectionSystem xgboostSystem;

    @PostConstruct
    public void init() {
        try {
            logger.info("Initialization of phishing detection systems...");

            rfSystem = new RFPhishingDetectionSystem(datasetPath);
            rfSystem.loadModel(rfModelPath);
            logger.info("Initialized Random Forest System.");

            svmSystem = new SVMPhishingDetectionSystem(datasetPath);
            svmSystem.loadModel(svmModelPath);
            logger.info("Initialized SVM System.");

            xgboostSystem = new XGBoostPhishingDetectionSystem(datasetPath);
            xgboostSystem.loadModel(xgboostModelPath);
            logger.info("Initialized XGBoost System.");

        } catch (Exception e) {
            logger.error("Error initializing phishing detection systems", e);
        }
    }

    /**
     * Analyzes an email using the Random Forest system
     */
    public PhishingResult analyzeWithRandomForest(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analysis with Random Forest: {}", emailText);
        return rfSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Analyzes an email using the SVM system
     */
    public PhishingResult analyzeWithSVM(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analysis with SVM: {}", emailText);
        return svmSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Analyzes an email using the XGBoost system
     */
    public PhishingResult analyzeWithXGBoost(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analysis with XGBoost: {}", emailText);
        return xgboostSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Saves user feedback for any classifier
     * This unified method handles saving feedback regardless of the classifier used
     *
     * @param emailText Text of the analyzed email
     * @param userFeedback User feedback (true = phishing, false = legitimate)
     * @param embedding BERT embedding of the email
     * @param numTokens Number of tokens in the email (as Integer instead of int)
     * @param classifier Identifier of the classifier used (rf, svm, xgboost)
     */
    public void saveFeedback(String emailText, boolean userFeedback, float[] embedding, Integer numTokens, String classifier) throws Exception {
        logger.info("Saving feedback for classifier: {}", classifier);

        //  create a feedback object with all the necessary data, including the classifier
        ProcessedEmailForJSON feedback = new ProcessedEmailForJSON(
                emailText,
                userFeedback,
                embedding,
                numTokens,
                new Date(),
                classifier
        );

        // Salviamo il feedback in un file JSON unico
        saveFeedbackToJson(feedback, classifier);

        logger.info("Feedback saved successfullyo");
    }

    /**
     * Saves the feedback in a single JSON file, checking for duplicates
     */
    private void saveFeedbackToJson(ProcessedEmailForJSON feedback, String classifier) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        String fileName = "feedback_dataset.json";

        File feedbackFile = new File(datasetPath + "/" + fileName);
        feedbackFile.getParentFile().mkdirs();// The directory must exist

        List<ProcessedEmailForJSON> existingFeedback = new ArrayList<>();

        //The directory must exist
        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of(bucketName, fileName);
        // Check if the file already exists in the bucket
        Blob blob = storage.get(blobId);
        if (blob != null && blob.exists()) {
            // Download the contents of the existing file
            byte[] content = blob.getContent();
            String jsonContent = new String(content, StandardCharsets.UTF_8);

            //Deserialize existing JSON content
            existingFeedback = mapper.readValue(jsonContent,
                    mapper.getTypeFactory().constructCollectionType(List.class, ProcessedEmailForJSON.class));
        }


        // Control to avoid duplicates
        boolean isDuplicate = false;
        for (ProcessedEmailForJSON existing : existingFeedback) {
            // Controlliamo se c'è un'email con testo identico, stesso feedback e stesso classificatore
            if (existing.getText().equals(feedback.getText()) && existing.isPhishing() == feedback.isPhishing()) {
                logger.info("Duplicate feedback found for classifier '{}', will not be added", classifier);
                isDuplicate = true;
                break;
            }
        }

        // only add the new feedback if it is not a duplicate
        if (!isDuplicate) {
            existingFeedback.add(feedback);

            //Convert the updated list to JSON and upload to the cloud
            String updatedJson = mapper.writeValueAsString(existingFeedback);
            BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType("application/json").build();
            storage.create(blobInfo, updatedJson.getBytes(StandardCharsets.UTF_8));

            logger.debug("Feedback saved in unified file on Cloud Storage: gs://{}/{}", bucketName, fileName);
        }
    }

}