package svm_classifier;


import weka.classifiers.functions.SMO;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.classifiers.Evaluation;
import weka.classifiers.functions.supportVector.RBFKernel;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class SVMPhishingClassifier {
    private SMO classifier;
    private Instances datasetStructure;

    public SVMPhishingClassifier() {
        //Initiliaze SVM
        classifier = new SMO();

        try {
            // configure the RBF (Radial Basis Function) kernel
            RBFKernel rbf = new RBFKernel();

            // Set gamma - a key parameter for the RBF kernel
            // A lower gamma value creates a smoother decision boundary
            rbf.setGamma(0.01);
            classifier.setKernel(rbf);

            //Configure the SMO parameters
            // C is the regularization parameter - it balances the training error
            // and the model complexity
            classifier.setC(1.0);

            //  Platt's calibration to obtain probability estimates
            classifier.setOptions(weka.core.Utils.splitOptions("-M"));

        } catch (Exception e) {
            System.err.println("SVM configuration error: " + e.getMessage());
        }

        setupDatasetStructure();
    }

    private void setupDatasetStructure() {
        ArrayList<Attribute> attributes = new ArrayList<>();

        // 768 attributes for BERT embedding
        for (int i = 0; i < 768; i++) {
            attributes.add(new Attribute("embedding_" + i));
        }

        attributes.add(new Attribute("contains_url"));
        attributes.add(new Attribute("contains_ip"));
        attributes.add(new Attribute("contains_non_ascii"));
        attributes.add(new Attribute("contains_spam_world"));

        attributes.add(new Attribute("sentiment_score"));
        attributes.add(new Attribute("sentiment_magnitude"));

        // Class attribute (phishing or legitimate)
        ArrayList<String> classValues = new ArrayList<>();
        classValues.add("phishing");
        classValues.add("legitimate");
        attributes.add(new Attribute("class", classValues));

        datasetStructure = new Instances("EmailDataset", attributes, 0);
        datasetStructure.setClassIndex(datasetStructure.numAttributes() - 1);
    }

    public void train(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        if (embeddings.size() != labels.size()) {
            throw new IllegalArgumentException("Number of embeddings and labels does not match");
        }

        Instances trainingData = new Instances(datasetStructure);

        // Create the training dataset with instance weights
        for (int i = 0; i < embeddings.size(); i++) {
            float[] embedding = embeddings.get(i);
            boolean isPhishing = labels.get(i);

            // Create an array with all the values ​​of the instance
            // Size is embedding.length + 1 for the class
            double[] values = new double[embedding.length + 1];

            // Copy the embedding
            for (int j = 0; j < embedding.length; j++) {
                values[j] = embedding[j];
            }

            // Add the class (0 for phishing, 1 for legitimate)
            values[embedding.length] = isPhishing ? 0.0 : 1.0;


            // Create the instance with weight
            // Give more weight to Italian emails (if necessary)
            Instance instance = new DenseInstance(1.0, values);
            trainingData.add(instance);
        }

        //  train the classifier
        classifier.buildClassifier(trainingData);
    }

    public boolean classify(float[] embedding) throws Exception {
        double[] values = new double[embedding.length];
        int index = 0;
        for (float value : embedding) {
            values[index++] = value;
        }

        Instance instance = new DenseInstance(1.0, values);
        instance.setDataset(datasetStructure);

        // classify the instance
        double prediction = classifier.classifyInstance(instance);
        return prediction == 0.0; // 0.0 = phishing, 1.0 = legitimate
    }

    public void evaluate(List<float[]> embeddings, List<Boolean> labels) throws Exception {
        Instances dataset = new Instances(datasetStructure);

        for (int i = 0; i < embeddings.size(); i++) {
            float[] embedding = embeddings.get(i);
            boolean isPhishing = labels.get(i);

            double[] values = new double[embedding.length + 1];

            for (int j = 0; j < embedding.length; j++) {
                values[j] = embedding[j];
            }
            values[embedding.length] = isPhishing ? 0.0 : 1.0;

            dataset.add(new DenseInstance(1.0, values));
        }


        Evaluation eval = new Evaluation(dataset);
        eval.evaluateModel(classifier, dataset);

        // Print the detailed results
        double tp =0, fp=0, tn=0, fn=0;
        tp= eval.truePositiveRate(1);
        fp = eval.falsePositiveRate(1);
        tn = eval.trueNegativeRate(1);
        fn = eval.falseNegativeRate(1);

        System.out.println("True Positives SVM: " + eval.numTruePositives(1));
        System.out.println("False Positives SVM: " + eval.numFalsePositives(1));
        System.out.println("True Negatives SVM: " + eval.numTrueNegatives(1));
        System.out.println("False Negatives SVM: " + eval.numFalseNegatives(1));

        double accuracy = (double)(tp + tn) / (tp + fp + tn + fn);
        double precision = tp == 0 ? 0 : (double)tp / (tp + fp);
        double recall = tp == 0 ? 0 : (double)tp / (tp + fn);
        double f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);

        System.out.println("=== Validation results ===");
        System.out.println("Accuracy: " + accuracy);
        System.out.println("Precision: " + precision);
        System.out.println("Recall: " + recall);
        System.out.println("F1 Score: " + f1);
    }

    /**
     * Save the model
     */
    public void saveModel(String filepath) throws Exception {
        weka.core.SerializationHelper.write(filepath, classifier);
    }

    /**
     * Load the model
     */
    public void loadModel(String filepath) throws Exception {
        classifier = (SMO) weka.core.SerializationHelper.read(filepath);
    }
}
