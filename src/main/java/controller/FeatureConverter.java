package controller;

import model.MailData;

import java.util.ArrayList;
import java.util.List;

public class FeatureConverter {
    public static float[] convertMailDataToFeatures(MailData mailData) {
        // List of features to extract from MailData
        List<Float> features = new ArrayList<>();

        // Add the numeric features
        features.add(mailData.getLinks().isEmpty() ? 0.0f : 1.0f);
        features.add(mailData.isContainsNonAsciiChars() ? 1.0f : 0.0f);
        features.add(mailData.isContainsIpAsUrl() ? 1.0f : 0.0f);
        features.add(mailData.isContainsSpam() ? 1.0f : 0.0f);

        features.add(mailData.getSentimentMagnitude());
        features.add(mailData.getSentimentScore());

        // convert the List<Float> to float[]
        float[] featureArray = new float[features.size()];
        for (int i = 0; i < features.size(); i++) {
            featureArray[i] = features.get(i);
        }

        return featureArray;
    }

    public static float[] combineFeatures(float[] bertEmbedding, MailData mailData) {
        float[] additionalFeatures = convertMailDataToFeatures(mailData);

        // Create the new combined array
        float[] combinedFeatures = new float[bertEmbedding.length + additionalFeatures.length];

        // Copiamo l'embedding BERT
        System.arraycopy(bertEmbedding, 0, combinedFeatures, 0, bertEmbedding.length);

        //  add the new features
        System.arraycopy(additionalFeatures, 0, combinedFeatures,
                bertEmbedding.length, additionalFeatures.length);

        return combinedFeatures;
    }
}
