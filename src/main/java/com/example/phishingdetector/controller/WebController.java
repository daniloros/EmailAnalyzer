package com.example.phishingdetector.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("pageTitle", "Phishing Detection System");
        return "index";
    }

    @GetMapping("/analyzer")
    public String analyzer(Model model, HttpSession session) {
        model.addAttribute("pageTitle", "Email Analyzer");

        // Retrieve data from session if available
        if (session.getAttribute("emailContent") != null) {
            model.addAttribute("emailContent", session.getAttribute("emailContent"));
            model.addAttribute("emailSubject", session.getAttribute("emailSubject"));
            model.addAttribute("urls", session.getAttribute("urls"));

            // Pulisci la sessione
            session.removeAttribute("emailContent");
            session.removeAttribute("emailSubject");
            session.removeAttribute("urls");
        }

        return "analyzer";
    }

    @GetMapping("/comparison")
    public String comparison(Model model, HttpSession session) {
        model.addAttribute("pageTitle", "Classifier Comparison");

        //Retrieve data from session if available
        if (session.getAttribute("emailContent") != null) {
            model.addAttribute("emailContent", session.getAttribute("emailContent"));
            model.addAttribute("emailSubject", session.getAttribute("emailSubject"));
            model.addAttribute("urls", session.getAttribute("urls"));

            // Pulisci la sessione
            session.removeAttribute("emailContent");
            session.removeAttribute("emailSubject");
            session.removeAttribute("urls");
        }

        return "comparison";
    }


}