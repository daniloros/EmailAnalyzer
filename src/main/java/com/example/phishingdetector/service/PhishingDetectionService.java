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
            logger.info("Inizializzazione dei sistemi di rilevamento phishing...");

            // Inizializza Random Forest
            rfSystem = new RFPhishingDetectionSystem(datasetPath);
            rfSystem.loadModel(rfModelPath);
            logger.info("Sistema Random Forest inizializzato.");

            // Inizializza SVM
            svmSystem = new SVMPhishingDetectionSystem(datasetPath);
            svmSystem.loadModel(svmModelPath);
            logger.info("Sistema SVM inizializzato.");

            // Inizializza XGBoost
            xgboostSystem = new XGBoostPhishingDetectionSystem(datasetPath);
            xgboostSystem.loadModel(xgboostModelPath);
            logger.info("Sistema XGBoost inizializzato.");

        } catch (Exception e) {
            logger.error("Errore durante l'inizializzazione dei sistemi di rilevamento phishing", e);
        }
    }

    /**
     * Analizza una email utilizzando il sistema Random Forest
     */
    public PhishingResult analyzeWithRandomForest(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analisi con Random Forest: {}", emailText);
        return rfSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Analizza una email utilizzando il sistema SVM
     */
    public PhishingResult analyzeWithSVM(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analisi con SVM: {}", emailText);
        return svmSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Analizza una email utilizzando il sistema XGBoost
     */
    public PhishingResult analyzeWithXGBoost(String emailText, List<String> extractedUrls) throws Exception {
        logger.debug("Analisi con XGBoost: {}", emailText);
        return xgboostSystem.analyzeEmail(emailText, extractedUrls);
    }

    /**
     * Salva il feedback dell'utente per qualsiasi classificatore
     * Questo metodo unificato gestisce il salvataggio del feedback indipendentemente dal classificatore utilizzato
     *
     * @param emailText Testo dell'email analizzata
     * @param userFeedback Feedback dell'utente (true = phishing, false = legittima)
     * @param embedding Embedding BERT dell'email
     * @param numTokens Numero di token nell'email (come Integer invece di int)
     * @param classifier Identificatore del classificatore utilizzato (rf, svm, xgboost)
     */
    public void saveFeedback(String emailText, boolean userFeedback, float[] embedding, Integer numTokens, String classifier) throws Exception {
        logger.info("Salvando feedback per classificatore: {}", classifier);

        // Creiamo un oggetto feedback con tutti i dati necessari, incluso il classificatore
        ProcessedEmailForJSON feedback = new ProcessedEmailForJSON(
                emailText,
                userFeedback,
                embedding,
                numTokens,
                new Date(),
                classifier // Aggiungiamo il classificatore all'oggetto
        );

        // Salviamo il feedback in un file JSON unico
        saveFeedbackToJson(feedback, classifier);

        logger.info("Feedback salvato con successo");
    }

    /**
     * Salva il feedback in un unico file JSON, controllando per duplicati
     */
    private void saveFeedbackToJson(ProcessedEmailForJSON feedback, String classifier) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        String fileName = "feedback_dataset.json";

        File feedbackFile = new File(datasetPath + "/" + fileName);
        feedbackFile.getParentFile().mkdirs();// la directory deve esistere

        List<ProcessedEmailForJSON> existingFeedback = new ArrayList<>();

        //inizializzo il cloud storage
        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of(bucketName, fileName);
        // Controlla se il file esiste già nel bucket
        Blob blob = storage.get(blobId);
        if (blob != null && blob.exists()) {
            // Scarica il contenuto del file esistente
            byte[] content = blob.getContent();
            String jsonContent = new String(content, StandardCharsets.UTF_8);

            // Deserializza il contenuto JSON esistente
            existingFeedback = mapper.readValue(jsonContent,
                    mapper.getTypeFactory().constructCollectionType(List.class, ProcessedEmailForJSON.class));
        }


        // Controllo per evitare duplicati
        boolean isDuplicate = false;
        for (ProcessedEmailForJSON existing : existingFeedback) {
            // Controlliamo se c'è un'email con testo identico, stesso feedback e stesso classificatore
            if (existing.getText().equals(feedback.getText()) && existing.isPhishing() == feedback.isPhishing()) {
                logger.info("Feedback duplicato trovato per classificatore '{}', non verrà aggiunto", classifier);
                isDuplicate = true;
                break;
            }
        }

        // Aggiungiamo il nuovo feedback solo se non è un duplicato
        if (!isDuplicate) {
            existingFeedback.add(feedback);

            // Converti la lista aggiornata in JSON e carico sul cloud
            String updatedJson = mapper.writeValueAsString(existingFeedback);
            BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType("application/json").build();
            storage.create(blobInfo, updatedJson.getBytes(StandardCharsets.UTF_8));

            logger.debug("Feedback salvato nel file unificato su Cloud Storage: gs://{}/{}", bucketName, fileName);
        }
    }

}