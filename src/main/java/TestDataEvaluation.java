import controller.EmailFeatureProcessor;
import model.ProcessedEmailForJSON;
import rf_classifier.RFPhishingClassifier;
import svm_classifier.SVMPhishingClassifier;
import xgboost_classifier.XGBoostPhishingClassifier;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class TestDataEvaluation {
    public static void main(String[] args) {
        try {
            // Configuration
            String datasetPath = "src/main/resources/dataset/evaluation_set";
            String inputJsonPath = "src/main/resources/dataset/evaluation_set/evalution_set_with_sentiment_NOT_evaluated.json";
            String outputFileName = "/evaluation_set_EVALUATED.json";
            // Step 1: Process all emails once
            EmailFeatureProcessor processor = new EmailFeatureProcessor(datasetPath);

            // Check if processed file already exists
            File processedFile = new File(datasetPath + outputFileName);
            if (!processedFile.exists()) {
                System.out.println("Processing emails and extracting features...");
                processor.processEmails(inputJsonPath, outputFileName);
            } else {
                System.out.println("Using existing processed email features...");
            }

            // Step 2: Load the processed data
            List<ProcessedEmailForJSON> processedEmails = processor.loadProcessedEmails(outputFileName);
            System.out.println("Loaded " + processedEmails.size() + " processed emails");

            // Step 3: Prepare data for training (same data for all classifiers)
            List<float[]> embeddings = new ArrayList<>();
            List<Boolean> labels = new ArrayList<>();

            for (ProcessedEmailForJSON email : processedEmails) {
                embeddings.add(email.getEmbedding());
                labels.add(email.isPhishing());
            }

            // Step 4: Train all models using the same processed data

            String rfModelPath = "src/main/resources/models/rf_model.model";
            String svmModelPath = "src/main/resources/models/svm_model.model";
            String xgboostModelPath = "src/main/resources/models/xgboost_model.model";


            // Train Random Forest
            System.out.println("\nTraining Random Forest...");
            RFPhishingClassifier rfClassifier = new RFPhishingClassifier();
            rfClassifier.loadModel(rfModelPath);
            rfClassifier.evaluate(embeddings, labels);


            // Train SVM
            System.out.println("\nTraining SVM...");
            SVMPhishingClassifier svmClassifier = new SVMPhishingClassifier();
            svmClassifier.loadModel(svmModelPath);
            svmClassifier.evaluate(embeddings, labels);

            // Train XGBoost
            System.out.println("\nTraining XGBoost...");
            XGBoostPhishingClassifier xgbClassifier = new XGBoostPhishingClassifier();
            xgbClassifier.loadModel(xgboostModelPath);
            xgbClassifier.evaluate(embeddings, labels);
            System.out.println("XGBoost model saved successfully");


        } catch (Exception e) {
            System.err.println("Error during training process:");
            e.printStackTrace();
        }
    }
}
