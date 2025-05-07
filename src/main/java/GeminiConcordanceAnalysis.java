import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.example.phishingdetector.service.GeminiService;
import controller.EmailFeatureProcessor;
import model.ProcessedEmailForJSON;
import rf_classifier.RFPhishingClassifier;
import svm_classifier.SVMPhishingClassifier;
import xgboost_classifier.XGBoostPhishingClassifier;

/**
 * Concordance analysis between phishing classifiers and Gemini ratings.
 * This class processes a dataset of emails, applies the three classifiers (RF, SVM, XGBoost),
 * sends the data to Gemini once per email and compares the results.
 */
public class GeminiConcordanceAnalysis {

    private static final String DATASET_PATH = "src/main/resources/dataset/evaluation_set";
    private static final String OUTPUT_FILE_NAME = "/validation_set_EVALUATED_400.json";
    private static final String RF_MODEL_PATH = "rf_model_2000.model";
    private static final String SVM_MODEL_PATH = "svm_model_2000.model";
    private static final String XGBOOST_MODEL_PATH = "xgboost_model_2000.model";

    // Number of emails to be analyzed with Gemini (limited for practical reasons)
    private static final int MAX_EMAILS_TO_ANALYZE = 20;

    // Rate Limiting per Gemini API
    private static final int MAX_REQUESTS_PER_MINUTE = 9;
    private static final int MAX_REQUESTS_PER_DAY = 500;
    private static final long MINUTE_IN_MILLIS = 60 * 1000;

    private final Queue<Long> requestTimestamps = new ConcurrentLinkedQueue<>();
    private final Map<LocalDate, AtomicInteger> dailyRequestCounts = new ConcurrentHashMap<>();
    private final Object rateLimitLock = new Object();

    private RFPhishingClassifier rfClassifier;
    private SVMPhishingClassifier svmClassifier;
    private XGBoostPhishingClassifier xgbClassifier;

    private GeminiService geminiService;

    private EmailFeatureProcessor processor;

    private static final String[] CLASSIFIER_NAMES = {"Random Forest", "SVM", "XGBoost"};

    public static void main(String[] args) {
        try {
            GeminiConcordanceAnalysis analysis = new GeminiConcordanceAnalysis();
            analysis.runAnalysis();
        } catch (Exception e) {
            System.err.println("Error during concordance analysis with Gemini:");
            e.printStackTrace();
        }
    }

    public GeminiConcordanceAnalysis() throws Exception {
        System.out.println("Initializing classifiers and Gemini...");

        processor = new EmailFeatureProcessor(DATASET_PATH);

        rfClassifier = new RFPhishingClassifier();
        svmClassifier = new SVMPhishingClassifier();
        xgbClassifier = new XGBoostPhishingClassifier();

        rfClassifier.loadModel(RF_MODEL_PATH);
        svmClassifier.loadModel(SVM_MODEL_PATH);
        xgbClassifier.loadModel(XGBOOST_MODEL_PATH);

        geminiService = new GeminiService();
    }


    public void runAnalysis() throws Exception {
        // load evalutaed email
        List<ProcessedEmailForJSON> processedEmails = processor.loadProcessedEmails(OUTPUT_FILE_NAME);
        System.out.println("Load " + processedEmails.size() + " email ");

        // Metrics for each classifier [TP, TN, FP, FN]
        int[][] classifierPerformance = new int[3][4];

        // Gemini concordance metrics for each category and classifier.
        // [TP agree, TP disagree, TN agree, TN disagree, FP agree, FP disagree, FN agree, FN disagree]
        int[][] geminiConcordance = new int[3][8];

        // First step: rank all emails and store the results
        List<Map<String, Boolean>> allClassifications = new ArrayList<>();

        System.out.println("\nMail classification with algorithms");
        for (ProcessedEmailForJSON email : processedEmails) {
            Map<String, Boolean> emailClassifications = new HashMap<>();

            boolean actualLabel = email.isPhishing();
            boolean rfResult = rfClassifier.classify(email.getEmbedding());
            boolean svmResult = svmClassifier.classify(email.getEmbedding());
            boolean xgbResult = xgbClassifier.classify(email.getEmbedding());

            emailClassifications.put("TrueLabel", actualLabel);
            emailClassifications.put("RF", rfResult);
            emailClassifications.put("SVM", svmResult);
            emailClassifications.put("XGBoost", xgbResult);

            allClassifications.add(emailClassifications);

            updateClassifierMetrics(classifierPerformance[0], rfResult, actualLabel);
            updateClassifierMetrics(classifierPerformance[1], svmResult, actualLabel);
            updateClassifierMetrics(classifierPerformance[2], xgbResult, actualLabel);
        }

        System.out.println("\n=== Performanc===");
        System.out.println("| Classificaator | TP  | TN  | FP  | FN  | Accuracy | Precision | Recall |");
        System.out.println("|----------------|-----|-----|-----|-----|----------|-----------|--------|");

        for (int i = 0; i < CLASSIFIER_NAMES.length; i++) {
            int tp = classifierPerformance[i][0];
            int tn = classifierPerformance[i][1];
            int fp = classifierPerformance[i][2];
            int fn = classifierPerformance[i][3];

            double accuracy = (double)(tp + tn) / (tp + tn + fp + fn);
            double precision = tp == 0 ? 0 : (double)tp / (tp + fp);
            double recall = tp == 0 ? 0 : (double)tp / (tp + fn);

            System.out.printf("| %-14s | %3d | %3d | %3d | %3d | %8.2f | %9.2f | %6.2f |\n",
                    CLASSIFIER_NAMES[i], tp, tn, fp, fn, accuracy, precision, recall);
        }

        // Second phase: analysis with Gemini (for a subset)
        int emailsToAnalyze = Math.min(MAX_EMAILS_TO_ANALYZE, processedEmails.size());

        System.out.println("\nAnalyze with Gemini for " + processedEmails.size() + " email...");
        System.out.println("(Limits for API: max " + MAX_REQUESTS_PER_MINUTE + " request/min, "
                + MAX_REQUESTS_PER_DAY + " request/day)");

        int totalGeminiRequests = 0;

        for (int i = 0; i < processedEmails.size(); i++) {
            ProcessedEmailForJSON email = processedEmails.get(i);
            Map<String, Boolean> classifications = allClassifications.get(i);
            boolean actualLabel = classifications.get("TrueLabel");
            boolean rfResult = classifications.get("RF");
            boolean svmResult = classifications.get("SVM");
            boolean xgbResult = classifications.get("XGBoost");

            List<String> urls = extractUrlsFromEmail(email.getText());

            System.out.println("\n Analyzing  " + (i+1) + "/" + processedEmails.size() +
                    " (Real label: " + (actualLabel ? "PHISHING" : "LEGITIMATE") + ")");
            System.out.println("  - RF: " + (rfResult ? "PHISHING" : "LEGITIMATE"));
            System.out.println("  - SVM: " + (svmResult ? "PHISHING" : "LEGITIMATE"));
            System.out.println("  - XGBoost: " + (xgbResult ? "PHISHING" : "LEGITIMATE"));

            try {
                // Wait until a new request can be made
                waitForRateLimit();
                totalGeminiRequests++;


                CompletableFuture<String> geminiAnalysisFuture = geminiService.analyzeForCompareEmailWithGemini(
                        email.getText(), urls, email.getEmbedding());

                String geminiAnalysis = geminiAnalysisFuture.get(30, TimeUnit.SECONDS);
                boolean geminiResult = extractGeminiVerdict(geminiAnalysis);

                System.out.println("  - Gemini: " + (geminiResult ? "PHISHING" : "LEGITIMATE"));


                updateGeminiConcordance(geminiConcordance[0], rfResult, geminiResult, actualLabel);    // RF
                updateGeminiConcordance(geminiConcordance[1], svmResult, geminiResult, actualLabel);   // SVM
                updateGeminiConcordance(geminiConcordance[2], xgbResult, geminiResult, actualLabel);   // XGBoost

            } catch (InterruptedException e) {
                System.err.println("Interruption while waiting for rate limit: " + e.getMessage());
                continue;
            } catch (Exception e) {
                System.err.println("Error in analysis with Gemini: " + e.getMessage());
            }
        }

        System.out.println("\n=== Analysis of concordance with Gemini ===");
        System.out.println("total request to Gemini: " + totalGeminiRequests);
        printGeminiConcordanceTable(geminiConcordance, CLASSIFIER_NAMES);
    }


    private void waitForRateLimit() throws InterruptedException {
        LocalDate today = LocalDate.now();
        AtomicInteger dailyCount = dailyRequestCounts.computeIfAbsent(today, k -> new AtomicInteger(0));

        // Verifica limite giornaliero
        if (dailyCount.get() >= MAX_REQUESTS_PER_DAY) {
            System.out.println(" WARNING: Daily API limit reached. (" +
                    dailyCount.get() + "/" + MAX_REQUESTS_PER_DAY + ")");
            System.out.println(" Requests will resume tomorrow. Press Ctrl+C to finish.");

            // Attendere fino alla mezzanotte del giorno dopo
            long millisecondsUntilMidnight = calculateMillisecondsUntilMidnight();
            System.out.println("  wait for " + (millisecondsUntilMidnight / 1000 / 60) +
                    " minutes until midnight");
            Thread.sleep(millisecondsUntilMidnight + 1000); //
            return;
        }

        // Minute limit check
        synchronized (rateLimitLock) {
            long currentTime = System.currentTimeMillis();

            // Cleaning old timestamps (more than one minute).
            while (!requestTimestamps.isEmpty() && requestTimestamps.peek() < currentTime - MINUTE_IN_MILLIS) {
                requestTimestamps.poll();
            }

            // If we have reached the minute limit, wait exactly 1.1 minutes
            if (requestTimestamps.size() >= MAX_REQUESTS_PER_MINUTE) {
                System.out.println("  Minute limit reached (" +
                        requestTimestamps.size() + "/" + MAX_REQUESTS_PER_MINUTE + ")");
                System.out.println("  Waiting 1.1 minutes before the next request....");

                Thread.sleep(70 * 1000);

                currentTime = System.currentTimeMillis();
                while (!requestTimestamps.isEmpty() && requestTimestamps.peek() < currentTime - MINUTE_IN_MILLIS) {
                    requestTimestamps.poll();
                }
            }

            registerApiRequest();
        }
    }


    private long calculateMillisecondsUntilMidnight() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime midnight = now.toLocalDate().plusDays(1).atStartOfDay();
        return Duration.between(now, midnight).toMillis();
    }

    private boolean extractGeminiVerdict(String geminiAnalysis) {
        String cleanResponse = geminiAnalysis.trim().toUpperCase();

        if (cleanResponse.contains("PHISHING")) {
            return true;
        } else if (cleanResponse.contains("LEGITIMATE")) {
            return false;
        }

        // In case the answer is not exactly as requested
        // We count the occurrences of words related to phishing
        int phishingSignals = countOccurrences(cleanResponse, "PHISH", "SCAM", "FRAUD", "MALICIOUS");
        int legitimateSignals = countOccurrences(cleanResponse, "LEGIT", "SAFE", "AUTHENTIC", "GENUINE");

        return phishingSignals > legitimateSignals;
    }

    private int countOccurrences(String text, String... keywords) {
        int count = 0;
        for (String keyword : keywords) {
            int index = 0;
            while ((index = text.indexOf(keyword, index)) != -1) {
                count++;
                index += keyword.length();
            }
        }
        return count;
    }


    private List<String> extractUrlsFromEmail(String emailText) {
        List<String> urls = new ArrayList<>();
        Pattern pattern = Pattern.compile("(https?://|www\\.)([-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6})\\b[-a-zA-Z0-9()@:%_+.~#?&/=\\-]*");
        Matcher matcher = pattern.matcher(emailText);
        while (matcher.find()) {
            urls.add(matcher.group());
        }
        return urls;
    }

    /**
     * Registers an API request for rate limiting.
     */
    private void registerApiRequest() {
        synchronized (rateLimitLock) {
            LocalDate today = LocalDate.now();
            long currentTime = System.currentTimeMillis();

            // Add timestamps to track requests per minute
            requestTimestamps.add(currentTime);

            // Increases the daily counter
            AtomicInteger dailyCount = dailyRequestCounts.computeIfAbsent(today, k -> new AtomicInteger(0));
            dailyCount.incrementAndGet();
        }
    }

    /**
     * Update the classifier metrics (TP, TN, FP, FN).
     */
    private void updateClassifierMetrics(int[] metrics, boolean prediction, boolean actualLabel) {
        if (prediction && actualLabel) {
            metrics[0]++; // TP
        } else if (!prediction && !actualLabel) {
            metrics[1]++; // TN
        } else if (prediction && !actualLabel) {
            metrics[2]++; // FP
        } else if (!prediction && actualLabel) {
            metrics[3]++; // FN
        }
    }

    /**
     * Update Gemini concordance metrics.
     */
    private void updateGeminiConcordance(int[] metrics, boolean classifierResult, boolean geminiResult, boolean actualLabel) {
        if (classifierResult && actualLabel) { // TP classificator
            if (geminiResult) {
                metrics[0]++; // TP concordant
            } else {
                metrics[1]++; // TP discordant
            }
        } else if (!classifierResult && !actualLabel) { // TN classificator
            if (!geminiResult) {
                metrics[2]++; // TN concordant
            } else {
                metrics[3]++; // TN discordant
            }
        } else if (classifierResult && !actualLabel) { // FP classificator
            if (geminiResult) {
                metrics[4]++; // FP concordant (both are wrong)
            } else {
                metrics[5]++; // FP discordant (Gemini corrects)
            }
        } else if (!classifierResult && actualLabel) { // FN classificator
            if (!geminiResult) {
                metrics[6]++; // FN concordant (both are wrong)
            } else {
                metrics[7]++; // FN discordane (Gemini corrects)
            }
        }
    }

    /**
     * Print the concordance table with Gemini.
     */
    private void printGeminiConcordanceTable(int[][] metrics, String[] classifierNames) {
        System.out.println("| Category | concordance | RF | SVM | XGBoost |");
        System.out.println("|-----------|-------------|----|----|---------|");

        String[] categories = {"TP", "TN", "FP", "FN"};

        for (int i = 0; i < 4; i++) {
            // Concordante
            System.out.printf("| %-9s | concordance    | %2d | %2d | %2d     |\n",
                    categories[i], metrics[0][i*2], metrics[1][i*2], metrics[2][i*2]);

            // Discordante
            System.out.printf("| %-9s | discordance    | %2d | %2d | %2d     |\n",
                    categories[i], metrics[0][i*2+1], metrics[1][i*2+1], metrics[2][i*2+1]);
        }

        // Calculates and prints total concordances/discordances
        int[] totalConcordant = new int[3];
        int[] totalDiscordant = new int[3];

        for (int j = 0; j < 3; j++) {
            for (int i = 0; i < 4; i++) {
                totalConcordant[j] += metrics[j][i*2];    // Concordant
                totalDiscordant[j] += metrics[j][i*2+1];  // Discordant
            }
        }

        System.out.println("|-----------|-------------|----|----|---------|");
        System.out.printf("| %-9s | Concordant    | %2d | %2d | %2d     |\n",
                "TOTAL", totalConcordant[0], totalConcordant[1], totalConcordant[2]);
        System.out.printf("| %-9s | Discordant    | %2d | %2d | %2d     |\n",
                "TOTAL", totalDiscordant[0], totalDiscordant[1], totalDiscordant[2]);

        // Calculate concordance percentage
        System.out.println("|-----------|-------------|----|----|---------|");
        for (int j = 0; j < 3; j++) {
            int total = totalConcordant[j] + totalDiscordant[j];
            double concordancePercentage = total > 0 ? (double)totalConcordant[j] / total * 100 : 0;
            System.out.printf("| %-9s | Concordance  | %2.0f%% |     |         |\n",
                    classifierNames[j], concordancePercentage);
        }

        System.out.println("\nLegend:");
        System.out.println("Agreeing TPs: The email is phishing, the classifier says phishing, Gemini says phishing");
        System.out.println("Disagreeing TPs: The email is phishing, the classifier says phishing, Gemini says legitimate");
        System.out.println("Agreeing TNs: The email is legitimate, the classifier says legitimate, Gemini says legitimate");
        System.out.println("Disagreeing TNs: The email is legitimate, the classifier says legitimate, Gemini says phishing");
        System.out.println("Agreeing FPs: The email is legitimate, the classifier says phishing, Gemini says phishing (both are wrong)");
        System.out.println("Disagreeing FPs: The email is legitimate, the classifier says phishing, Gemini says legitimate (Gemini corrects)");
        System.out.println("Agreeing FNs: The email is phishing, the classifier says legitimate, Gemini says legitimate (both are wrong)");
        System.out.println("Disagreeing FNs: The email is phishing, the classifier says legitimate, Gemini says phishing (Gemini corrects)");

    }
}