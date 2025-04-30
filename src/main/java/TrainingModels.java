import controller.EmailFeatureProcessor;
import model.ProcessedEmailForJSON;
import rf_classifier.RFPhishingClassifier;
import svm_classifier.SVMPhishingClassifier;
import xgboost_classifier.XGBoostPhishingClassifier;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class TrainingModels {
    public static void main(String[] args) {
        try {
            // Configuration
            String datasetPath = "src/main/resources/dataset/training_set";
            String inputJsonPath = "src/main/resources/dataset/training_set/training_set_NOT_evaluated_2000.json";
            String outputFileName = "/training_set_EVALUATED_2000.json";

            // Step 1: Process all emails once
            EmailFeatureProcessor processor = new EmailFeatureProcessor(datasetPath);

            // Check if processed file already exists
            File processedFile = new File(datasetPath + outputFileName);
            if (!processedFile.exists()) {
                System.out.println("Processing emails and extracting features...");
                processor.processEmails(inputJsonPath, outputFileName );
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

            // Train Random Forest
            System.out.println("\nTraining Random Forest...");
            RFPhishingClassifier rfClassifier = new RFPhishingClassifier();
            rfClassifier.train(embeddings, labels);
//            rfClassifier.evaluate(embeddings, labels);
            rfClassifier.saveModel("rf_model_2000.model");
            System.out.println("Random Forest model saved successfully");

            // Train SVM
            System.out.println("\nTraining SVM...");
            SVMPhishingClassifier svmClassifier = new SVMPhishingClassifier();
            svmClassifier.train(embeddings, labels);
//            svmClassifier.evaluate(embeddings, labels);
            svmClassifier.saveModel("svm_model_2000.model");
            System.out.println("SVM model saved successfully");

            // Train XGBoost
            System.out.println("\nTraining XGBoost...");
            XGBoostPhishingClassifier xgbClassifier = new XGBoostPhishingClassifier();
            xgbClassifier.train(embeddings, labels);
//            xgbClassifier.evaluate(embeddings, labels);
            xgbClassifier.saveModel("xgboost_model_2000.model");
            System.out.println("XGBoost model saved successfully");

            System.out.println("\nAll models trained and saved successfully!");

        } catch (Exception e) {
            System.err.println("Error during training process:");
            e.printStackTrace();
        }
    }
}
