package xgboost_classifier;


import weka.core.Attribute;
import weka.core.Instances;
import java.util.ArrayList;
import java.util.List;
import ml.dmlc.xgboost4j.java.Booster;
import ml.dmlc.xgboost4j.java.DMatrix;
import ml.dmlc.xgboost4j.java.XGBoost;
import ml.dmlc.xgboost4j.java.XGBoostError;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

public class XGBoostPhishingClassifier {
    // The XGBoost model
    private Booster booster;

    // Parameters for XGBoost
    private Map<String, Object> params;

    // The structure of our dataset (defines how our data is organized)
    private Instances datasetStructure;

    public XGBoostPhishingClassifier() {
        // Initialize XGBoost parameters
        params = new HashMap<>();
        params.put("objective", "binary:logistic");  // binary classification
        params.put("eval_metric", "error");          // evaluation metric
        params.put("eta", 0.1);                     // learning rate
        params.put("max_depth", 6);                 // maximum tree depth
        params.put("min_child_weight", 1);
        params.put("subsample", 0.8);
        params.put("colsample_bytree", 0.8);
        params.put("seed", 42);

        // prepare the structure that will contain our data
        setupDatasetStructure();
    }

    /**
     * Configures the structure of the dataset we will use.
     * This structure must reflect our data:
     * - 768 numerical attributes (one for each embedding dimension)
     * - Additional attributes (contains_url, contains_ip, etc.)
     * - 1 categorical attribute (the class: phishing or legitimate)
     */

    private void setupDatasetStructure() {
        ArrayList<Attribute> attributes = new ArrayList<>();

        // create 768 numeric attributes for the embedding
        for (int i = 0; i < 768; i++) {
            attributes.add(new Attribute("embedding_" + i));
        }

        // Additional attributes
        attributes.add(new Attribute("contains_url"));
        attributes.add(new Attribute("contains_ip"));
        attributes.add(new Attribute("contains_non_ascii"));
        attributes.add(new Attribute("contains_spam_world"));

        attributes.add(new Attribute("sentiment_score"));
        attributes.add(new Attribute("sentiment_magnitude"));

        // Create the class attribute (phishing or legitimate)
        ArrayList<String> classValues = new ArrayList<>();
        classValues.add("phishing");
        classValues.add("legitimate");
        attributes.add(new Attribute("class", classValues));

        // create the dataset structure
        datasetStructure = new Instances("EmailDataset", attributes, 0);
        // Indichiamo qual è l'attributo classe (l'ultimo)
        datasetStructure.setClassIndex(datasetStructure.numAttributes() - 1);
    }

    /**
     * Converts a list of embeddings and labels into a DMatrix for XGBoost
     */

    private DMatrix createDMatrix(List<float[]> embeddings, List<Boolean> labels) throws XGBoostError {
        int numRows = embeddings.size();
        int numCols = embeddings.get(0).length;

        // Converts the 2D matrix into a 1D array (row-major)

        float[] flatData = new float[numRows * numCols];
        float[] labelArray = new float[numRows];

        for (int i = 0; i < numRows; i++) {
            float[] row = embeddings.get(i);
            for (int j = 0; j < numCols; j++) {
                flatData[i * numCols + j] = row[j];
            }
            labelArray[i] = labels.get(i) ? 1.0f : 0.0f;  // true = phishing (1), false = legitimate (0)
        }

        DMatrix dMatrix = new DMatrix(flatData, numRows, numCols);
        dMatrix.setLabel(labelArray);
        return dMatrix;
    }

    /**
     * Trains the classifier on the provided data.
     * @param embeddings List of email embeddings
     * @param labels List of labels (true for phishing, false for legitimate)
     */

    public void train(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        //check that the data is consistent
        if (embeddings.size() != labels.size()) {
            throw new IllegalArgumentException("The number of embeddings and labels must match");
        }

        // Convert the data to the format required by XGBoost
        DMatrix trainMat = createDMatrix(embeddings, labels);

        //  define watchlists to monitor training
        Map<String, DMatrix> watches = new HashMap<>();
        watches.put("train", trainMat);

        // Number of boosting rounds
        int numRounds = 100;

        //  train the model
        booster = XGBoost.train(trainMat, params, numRounds, watches, null, null);

    }

    /**
     * Classifies a new embedding as phishing or legitimate
     * @param embedding The embedding to classify
     * @return true if the email is classified as phishing, false if legitimate
     */

    public boolean classify(float[] embedding) throws Exception {
        // convert the embedding to 1D format for the DMatrix
        DMatrix dTest = new DMatrix(embedding, 1, embedding.length);

        // make the prediction
        float[][] predictions = booster.predict(dTest);

        // XGBoost returns the probability of belonging to the positive class
        float probability = predictions[0][0];

        // If the probability is > 0.5, we classify it as phishing
        return probability > 0.5;
    }

    /**
     * Evaluates the model's performance
     */

    public void evaluate(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        // convert the data into the format required by XGBoost
        DMatrix evalMat = createDMatrix(embeddings, labels);

        // make predictions
        float[][] predictions = booster.predict(evalMat);

        //  calculate manual metrics (accuracy, precision, recall, F1)
        int tp = 0, fp = 0, tn = 0, fn = 0;

        for (int i = 0; i < predictions.length; i++) {
            boolean predicted = predictions[i][0] > 0.5;
            boolean actual = labels.get(i);

            if (predicted && actual) tp++;      // True Positive
            else if (predicted && !actual) fp++; // False Positive
            else if (!predicted && !actual) tn++; // True Negative
            else if (!predicted && actual) fn++;  // False Negative
        }

        // calculate the metrics

        double accuracy = (double)(tp + tn) / (tp + fp + tn + fn);
        double precision = tp == 0 ? 0 : (double)tp / (tp + fp);
        double recall = tp == 0 ? 0 : (double)tp / (tp + fn);
        double f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);

        // print the results
        System.out.println("=== Validation results ===");
        System.out.println("Accuracy: " + accuracy);
        System.out.println("Precision: " + precision);
        System.out.println("Recall: " + recall);
        System.out.println("F1 Score: " + f1);

        System.out.println("\n=== Confusion matrix ===");
        System.out.println("True Positives: " + tp);
        System.out.println("False Positives: " + fp);
        System.out.println("True Negatives: " + tn);
        System.out.println("False Negatives: " + fn);

    }

    /**
     * Save the trained model to file
     */
    public void saveModel(String filepath) throws Exception {
        if (booster != null) {
            booster.saveModel(new FileOutputStream(filepath));
        } else {
            throw new IllegalStateException("Untrained model");
        }
    }

    /**
     *Load a previously saved template
     */
    public void loadModel(String filepath) throws Exception {
        File modelFile = new File(filepath);
        if (modelFile.exists()) {
            booster = XGBoost.loadModel(new FileInputStream(modelFile));
        } else {
            throw new IllegalArgumentException("Template file not found: " + filepath);
        }
    }
}
