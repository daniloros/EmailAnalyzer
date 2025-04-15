package rf_classifier;

import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RFPhishingClassifier {
    // Classifier
    private Classifier classifier;

    // The structure of  dataset (defines how our data is organized)
    private Instances datasetStructure;

    public RFPhishingClassifier() {
        // Random Forest: Robust and handles high-dimensional data well
        classifier = new RandomForest();
        //  prepare the structure that will contain our data
        setupDatasetStructure();
    }

    /**
     * Configures the structure of the dataset we will use.
     * This structure must reflect our data:
     * - 768 numerical attributes (one for each embedding dimension)
     * - 1 categorical attribute (the class: phishing or legitimate)
     */

    private void setupDatasetStructure() {
        ArrayList<Attribute> attributes = new ArrayList<>();

        // create 768 numeric attributes for the embedding
        for (int i = 0; i < 768; i++) {
            attributes.add(new Attribute("embedding_" + i));
        }

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

        //  create the dataset structure
        datasetStructure = new Instances("EmailDataset", attributes, 0);
        // indicate what the class attribute is (the last one)
        datasetStructure.setClassIndex(datasetStructure.numAttributes() - 1);
    }

    /**
     * Trains the classifier on the provided data.
     * @param embeddings List of email embeddings
     * @param labels List of labels (true for phishing, false for legitimate)
     */

    public void train(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        //check that the data is consistent
        if (embeddings.size() != labels.size()) {
            throw new IllegalArgumentException("Il numero di embedding e labels deve corrispondere");
        }

        // create the training dataset
        Instances trainingData = new Instances(datasetStructure);

        // For each email in our dataset
        for (int i = 0; i < embeddings.size(); i++) {
            float[] embedding = embeddings.get(i);
            boolean isPhishing = labels.get(i);

            // Create an array with all the values ​​of the instance
            // +1 for the phishing class
            double[] values = new double[embedding.length + 1 ];

            //  copy the embedding
            for (int j = 0; j < embedding.length; j++) {
                values[j] = embedding[j];
            }

            // Add the class (0 for phishing, 1 for legitimate)
            values[embedding.length] = isPhishing ? 0.0 : 1.0;

            // Create the instance and add it to the dataset
            trainingData.add(new DenseInstance(1.0, values));
        }

        // train the classifier
        classifier.buildClassifier(trainingData);
    }

    /**
     * Classifies a new embedding as phishing or legitimate
     * @param embedding The embedding to classify
     * @return true if the email is classified as phishing, false if legitimate
     */
    public boolean classify(float[] embedding) throws Exception {
        //  create an instance for the new embedding
        double[] values = new double[embedding.length];

        //  copy the embedding
        for (int i = 0; i < embedding.length; i++) {
            values[i] = embedding[i];
        }

        // create the instance
        Instance instance = new DenseInstance(1.0, values);
        instance.setDataset(datasetStructure);

        //  classify the instance
        double prediction = classifier.classifyInstance(instance);

        //  convert the prediction to boolean
        return prediction == 0.0; // 0.0 = phishing, 1.0 = legitimate
    }

    /**
     * Evaluates the model's performance using cross-validation
     */

    public void evaluate(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        // Create the complete dataset
        Instances dataset = new Instances(datasetStructure);

        for (int i = 0; i < embeddings.size(); i++) {
            float[] embedding = embeddings.get(i);
            boolean isPhishing = labels.get(i);

            double[] values = new double[embedding.length + 1 ];
            for (int j = 0; j < embedding.length; j++) {
                values[j] = embedding[j];
            }
            values[embedding.length] = isPhishing ? 0.0 : 1.0;

            dataset.add(new DenseInstance(1.0, values));
        }

        Evaluation eval = new Evaluation(dataset);
        eval.evaluateModel(classifier, dataset);

        // Print the results
        System.out.println("=== Validation results ===");
        System.out.println(eval.toSummaryString());
        System.out.println("\n=== Confusion matrix===");
        System.out.println(eval.toMatrixString());

        System.out.println("\n=== Metriche Dettagliate ===");
        System.out.println("F-Measure: " + eval.weightedFMeasure());
        System.out.println("ROC Area: " + eval.weightedAreaUnderROC());
        System.out.println("Precision: " + eval.weightedPrecision());
        System.out.println("Recall: " + eval.weightedRecall());
    }

    /**
     * Saves the trained model to a file
     */

    public void saveModel(String filepath) throws Exception {
        SerializationHelper.write(filepath, classifier);
    }

    /**
     * Loads a previously saved model
     */
    public void loadModel(String filepath) throws Exception {
        classifier = (Classifier) SerializationHelper.read(filepath);
    }
}
