package com.example.phishingdetector.controller;

import com.example.phishingdetector.dto.ComparisonResponse;
import com.example.phishingdetector.dto.EmailRequest;
import com.example.phishingdetector.dto.EmailResponse;
import com.example.phishingdetector.dto.FeedbackRequest;
import com.example.phishingdetector.service.EmailParserService;
import com.example.phishingdetector.service.PhishingDetectionService;
import model.PhishingResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class PhishingControllerAPI {
    private static final Logger logger = LoggerFactory.getLogger(PhishingControllerAPI.class);

    @Autowired
    private PhishingDetectionService detectionService;

    @Autowired
    private EmailParserService emailParserService;

    private Map<String, PhishingResult> resultCache = new HashMap<>();

    @PostMapping("/analyze/rf")
    public ResponseEntity<EmailResponse> analyzeWithRandomForest(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithRandomForest(request.getText(), request.getExtractedUrls());
            String key = "rf-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "Random Forest",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Errore durante l'analisi con Random Forest", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/svm")
    public ResponseEntity<EmailResponse> analyzeWithSVM(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithSVM(request.getText(), request.getExtractedUrls());
            String key = "svm-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "SVM",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Errore durante l'analisi con SVM", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/xgboost")
    public ResponseEntity<EmailResponse> analyzeWithXGBoost(@RequestBody EmailRequest request) {
        try {
            PhishingResult result = detectionService.analyzeWithXGBoost(request.getText(), request.getExtractedUrls());
            String key = "xgboost-" + System.currentTimeMillis();
            resultCache.put(key, result);

            EmailResponse response = new EmailResponse(
                    result.getEmailText(),
                    result.isPhishing(),
                    "XGBoost",
                    summarizeFeatures(result.getEmbedding()),
                    result.getNum_token(),
                    key
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Errore durante l'analisi con XGBoost", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/analyze/compare")
    public ResponseEntity<ComparisonResponse> compareClassifiers(@RequestBody EmailRequest request) {
        try {
            PhishingResult rfResult = detectionService.analyzeWithRandomForest(request.getText(), request.getExtractedUrls());
            PhishingResult svmResult = detectionService.analyzeWithSVM(request.getText(), request.getExtractedUrls());
            PhishingResult xgboostResult = detectionService.analyzeWithXGBoost(request.getText(), request.getExtractedUrls());

            // Salviamo i risultati nella cache
            String rfKey = "rf-" + System.currentTimeMillis();
            String svmKey = "svm-" + System.currentTimeMillis();
            String xgbKey = "xgboost-" + System.currentTimeMillis();

            resultCache.put(rfKey, rfResult);
            resultCache.put(svmKey, svmResult);
            resultCache.put(xgbKey, xgboostResult);

            ComparisonResponse response = new ComparisonResponse(
                    rfResult.isPhishing(),
                    svmResult.isPhishing(),
                    xgboostResult.isPhishing(),
                    request.getText(),
                    rfResult.getNum_token(),
                    rfKey,
                    svmKey,
                    xgbKey
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Errore durante il confronto dei classificatori", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/feedback")
    public ResponseEntity<?> saveFeedback(@RequestBody FeedbackRequest request) {
        try {
            logger.info("Ricevuta richiesta di feedback: {}", request);

            // Verifichiamo se abbiamo questo risultato nella cache
            PhishingResult cachedResult = null;
            if (request.getResultId() != null && !request.getResultId().isEmpty()) {
                cachedResult = resultCache.get(request.getResultId());
            }

            if (cachedResult != null) {
                logger.info("Trovato risultato nella cache con ID: {}", request.getResultId());

                detectionService.saveFeedback(
                        cachedResult.getEmailText(),
                        request.isUserFeedback(),
                        cachedResult.getEmbedding(),
                        cachedResult.getNum_token(),
                        request.getClassifier()
                );
            } else {
                // Se non abbiamo il risultato in cache, procediamo comunque ma rianalizzando l'email
                logger.warn("Risultato non trovato nella cache, rianalizzando l'email");

                // Rianalizziamo l'email per ottenere tutti i dati necessari
                PhishingResult freshResult = null;
                String classifier = request.getClassifier().toLowerCase();

                if (classifier.contains("rf") || classifier.contains("random")) {
                    freshResult = detectionService.analyzeWithRandomForest(request.getEmailText(),null);
                } else if (classifier.contains("svm")) {
                    freshResult = detectionService.analyzeWithSVM(request.getEmailText(), null);
                } else if (classifier.contains("xgboost")) {
                    freshResult = detectionService.analyzeWithXGBoost(request.getEmailText(), null);
                } else {
                    // Default a Random Forest se il classificatore non è specificato correttamente
                    freshResult = detectionService.analyzeWithRandomForest(request.getEmailText(), null);
                }

                detectionService.saveFeedback(
                        freshResult.getEmailText(),
                        request.isUserFeedback(),
                        freshResult.getEmbedding(),
                        freshResult.getNum_token(),
                        request.getClassifier()
                );
            }

            return ResponseEntity.ok().body(Map.of("status", "success", "message", "Feedback salvato con successo"));
        } catch (Exception e) {
            logger.error("Errore durante il salvataggio del feedback", e);
            return ResponseEntity.internalServerError().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }


    //TODO: da eliminare, sotituito con l'EmailUploadController
    @PostMapping("/upload-eml")
    public ResponseEntity<?> handleEmlUpload(@RequestParam("emlFile") MultipartFile file) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Il file è vuoto"));
            }

            String fileName = file.getOriginalFilename();
            if (fileName == null || !fileName.toLowerCase().endsWith(".eml")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Il file deve essere in formato .eml"));
            }

            // Estrai il contenuto dell'email con il nuovo metodo che restituisce una mappa
            Map<String, Object> emailContent = emailParserService.parseEmlFile(file);

            // Restituisci il contenuto estratto
            return ResponseEntity.ok(emailContent);
        } catch (Exception e) {
            logger.error("Errore nell'elaborazione del file .eml", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    public PhishingResult getResultFromCache(String resultId) {
        return resultCache.get(resultId);
    }

    private String summarizeFeatures(float[] embedding) {
        // Restituiamo solo alcuni valori
        if (embedding.length > 5) {
            return "Dimensione: " + embedding.length + ", Primi valori: " +
                    Arrays.toString(Arrays.copyOfRange(embedding, 0, 5)) + "...";
        } else {
            return "Dimensione: " + embedding.length + ", Valori: " + Arrays.toString(embedding);
        }
    }
}