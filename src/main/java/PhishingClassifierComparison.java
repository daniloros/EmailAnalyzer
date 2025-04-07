import model.PhishingResult;
import model.TrainingEmail;
import rf_classifier.RFPhishingDetectionSystem;
import svm_classifier.SVMPhishingDetectionSystem;
import xgboost_classifier.XGBoostPhishingDetectionSystem;

public class PhishingClassifierComparison {
    public static void main(String[] args) {
        try {
            String datasetPath = "src/main/resources/dataset/processed";

            // Inizializziamo entrambi i sistemi
            RFPhishingDetectionSystem rfSystem = new RFPhishingDetectionSystem(datasetPath);
            SVMPhishingDetectionSystem svmSystem = new SVMPhishingDetectionSystem(datasetPath);
            XGBoostPhishingDetectionSystem xgbSystem = new XGBoostPhishingDetectionSystem(datasetPath);

            // Carichiamo i rispettivi modelli
            rfSystem.loadModel("src/main/resources/models/rf_model_test_new.model");
            svmSystem.loadModel("src/main/resources/models/svm_model_test.model");
            xgbSystem.loadModel("src/main/resources/models/xgboost_model_test.model");

            // Email di test
            TrainingEmail toAnalyze = new TrainingEmail();
            String testEmail = "Click here to see the Bang BusIt is wild!!!!!!\n" +
                    "tepyycemkckiflbsvpcyi\n"; // La tua email di test
            toAnalyze.setText(testEmail);



            // Confrontiamo le predizioni
            System.out.println("Random Forest ...");
            PhishingResult rfResult = rfSystem.analyzeEmail(testEmail, null);

            System.out.println("SVM ....");
            PhishingResult svmResult = svmSystem.analyzeEmail(testEmail, null);

            System.out.println("XGBoost ....");
            PhishingResult xgbResult = xgbSystem.analyzeEmail(testEmail, null);

            System.out.println("=== Confronto Classificatori ===");
            System.out.println("Random Forest predice: " + (rfResult.isPhishing() ? "PHISHING" : "LEGITTIMA"));
            System.out.println("SVM predice: " + (svmResult.isPhishing() ? "PHISHING" : "LEGITTIMA"));
            System.out.println("XGBoost predice: " + (xgbResult.isPhishing() ? "PHISHING" : "LEGITTIMA"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}