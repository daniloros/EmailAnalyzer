package com.example.phishingdetector.service;

import jakarta.mail.BodyPart;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmailParserService {
    private static final Logger logger = LoggerFactory.getLogger(EmailParserService.class);

    // Pattern to find URLs in plain text
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://|www\\.)([-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6})\\b[-a-zA-Z0-9()@:%_+.~#?&/=\\-]*"
    );

    /**
     * Extracts the textual content from a .eml file and the URLs found
     */
    public Map<String, Object> parseEmlFile(MultipartFile file) throws MessagingException, IOException {
        logger.info("Parsing the .eml file: {}", file.getOriginalFilename());

        // Create an empty session for parsing
        Session session = Session.getDefaultInstance(new Properties(), null);

        try (InputStream inputStream = file.getInputStream()) {
            //Create a MimeMessage from the file
            MimeMessage message = new MimeMessage(session, inputStream);

            // Extract the subject
            String subject = message.getSubject() != null ? message.getSubject() : "NO SUBJECT";

            // Extract the headers
            Enumeration<String> headerLines = message.getAllHeaderLines();
            List<String> headers = new ArrayList<>();
            while (headerLines.hasMoreElements()) {
                headers.add(headerLines.nextElement());
            }

            // Initialize variables to store contents
            String textContent = "";
            String htmlContent = "";
            List<String> extractedUrls = new ArrayList<>();

            // Check the content type and manage it accordingly
            if (message.isMimeType("text/plain")) {
                textContent = (String) message.getContent();
                extractedUrls.addAll(extractUrlsFromText(textContent));
            } else if (message.isMimeType("text/html")) {
                htmlContent = (String) message.getContent();
                extractedUrls.addAll(extractUrlsFromHtml(htmlContent));
                textContent = Jsoup.parse(htmlContent).text();
            } else if (message.isMimeType("multipart/*")) {
                Multipart multipart = (Multipart) message.getContent();
                for (int i = 0; i < multipart.getCount(); i++) {
                    BodyPart part = multipart.getBodyPart(i);
                    if (part.isMimeType("text/plain")) {
                        String content = (String) part.getContent();
                        textContent += content;
                        extractedUrls.addAll(extractUrlsFromText(content));
                    } else if (part.isMimeType("text/html")) {
                        String content = (String) part.getContent();
                        htmlContent += content;
                        extractedUrls.addAll(extractUrlsFromHtml(content));
                    }
                }

                // If only have HTML content, we extract the text
                if (textContent.isEmpty() && !htmlContent.isEmpty()) {
                    textContent = Jsoup.parse(htmlContent).text();
                }
            }

            // Preprocess content to remove duplicate spaces and newlines
            textContent = textContent.replaceAll("\\s{2,}", " ").replaceAll("\\n{2,}", "\n").trim();

            // Handle quoted-printable encoding if needed
            if (textContent.contains("Content-Transfer-Encoding: quoted-printable")) {
                logger.debug("Quoted-printable content detected, decoding...");
                textContent = decodeQuotedPrintable(textContent);
            }

            // Remove duplicates from URL list
            List<String> uniqueUrls = new ArrayList<>(new LinkedHashSet<>(extractedUrls));

            // Create the response map
            Map<String, Object> result = new HashMap<>();
            result.put("text", textContent);
            result.put("subject", subject);
            result.put("urls", uniqueUrls);

            return result;
        }
    }

    /**
     * Extracts URLs from HTML content using Jsoup
     */
    private List<String> extractUrlsFromHtml(String htmlContent) {
        List<String> urls = new ArrayList<>();

        Document doc = Jsoup.parse(htmlContent);

        // Extract URLs from tags <a>
        Elements links = doc.select("a[href]");
        for (Element link : links) {
            String url = link.attr("href");
            if (isValidUrl(url)) {
                urls.add(url);
            }
        }

        // Extract URL from <img> tag
        Elements images = doc.select("img[src]");
        for (Element img : images) {
            String url = img.attr("src");
            if (isValidUrl(url)) {
                urls.add(url);
            }
        }

        // Search URLs in the text of all items
        String textContent = doc.text();
        urls.addAll(extractUrlsFromText(textContent));

        return urls;
    }

    /**
     * Extracts URLs from plain text using regex
     */

    public List<String> extractUrlsFromText(String text) {
        List<String> urls = new ArrayList<>();

        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            urls.add(matcher.group());
        }

        return urls;
    }

    /**
     * Checks if a string is a valid URL
     */

    private boolean isValidUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        // Ignore internal anchors and javascript
        if (url.startsWith("#") || url.startsWith("javascript:")) {
            return false;
        }

        // Accepts http/https or URLs starting with www.
        return url.startsWith("http://") || url.startsWith("https://") || url.startsWith("www.");
    }

    /**
     * Decodes text in quoted-printable format
     */
    private String decodeQuotedPrintable(String text) {
        // Simplified implementation of quoted-printable decoding
        return text.replaceAll("=[0-9A-F]{2}", " ");
    }
}