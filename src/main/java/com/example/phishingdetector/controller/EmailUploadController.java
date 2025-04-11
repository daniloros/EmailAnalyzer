package com.example.phishingdetector.controller;

import com.example.phishingdetector.service.EmailParserService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@Controller
public class EmailUploadController {
    private static final Logger logger = LoggerFactory.getLogger(EmailUploadController.class);

    @Autowired
    private EmailParserService emailParserService;

    @GetMapping("/upload")
    public String showUploadForm(@RequestParam(value = "origin", required = false, defaultValue = "analyzer") String origin, Model model) {
        model.addAttribute("origin", origin);
        return "upload-form";
    }


    @PostMapping("/upload-email")
    public String handleEmailUpload(@RequestParam("emailFile") MultipartFile file,
                                    @RequestParam(value = "origin", required = false, defaultValue = "analyzer") String origin,
                                    Model model, HttpSession session) {
        try {
            if (file.isEmpty()) {
                model.addAttribute("error", "Il file caricato è vuoto");
                return "upload-form";
            }

            String fileName = file.getOriginalFilename();
            if (fileName == null || !fileName.toLowerCase().endsWith(".eml")) {
                model.addAttribute("error", "Il file deve essere in formato .eml");
                return "upload-form";
            }

            // Extract Email Content
            Map<String, Object> parsedContent = emailParserService.parseEmlFile(file);

            // Save session data
            session.setAttribute("emailContent", parsedContent.get("text"));
            session.setAttribute("emailSubject", parsedContent.get("subject"));
            session.setAttribute("urls", parsedContent.get("urls"));

            // Pass to model
            model.addAttribute("emailContent", parsedContent.get("text"));
            model.addAttribute("emailSubject", parsedContent.get("subject"));
            model.addAttribute("urls", parsedContent.get("urls"));
            model.addAttribute("origin", origin);

            return "email-content";
        } catch (Exception e) {
            logger.error("Elaboration email file error", e);
            model.addAttribute("error", "Elaboration email file error" + e.getMessage());
            return "upload-form";
        }
    }

}