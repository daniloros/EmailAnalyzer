package controller;


import model.MailData;
import org.apache.commons.validator.routines.UrlValidator;

import java.nio.charset.Charset;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailLinkExtractor {
    private String emailText;


    public EmailLinkExtractor(String emailText) {
        this.emailText = emailText;
    }

    public void extractLinkFeatures(MailData mailData, List<String> preExtractedUrls) {
        if (preExtractedUrls != null && !preExtractedUrls.isEmpty()) {
            // Parse pre-extracted URLs
            for (String url : preExtractedUrls) {
                analyzeUrl(url, mailData);
            }
        }
        //extract link from text
        findLinkInText(emailText, mailData);
    }


    private static void findLinkInText(String text, MailData mailData) {

        String urlRegex = "(https?://|www\\.)([-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6})\\b[-a-zA-Z0-9()@:%_+.~#?&/=\\-]*";

        Pattern pattern = Pattern.compile(urlRegex);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String originalUrl = matcher.group();

            // If the link is an IP, we check with the isValidIP method
            if (isValidIP(originalUrl)) {
                mailData.setContainsIpAsUrl(true);
                continue;
            }


            try {
                if (isValidURL(originalUrl)) {
                    mailData.setLink(originalUrl);
                    if (containsNonASCIICharacters(originalUrl)) {
                        mailData.setContainsNonAsciiChars(true);
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
    }

    private static boolean isValidURL(String url) {
        // Enable http and https
        String[] schemes = {"http", "https"};
        UrlValidator urlValidator = new UrlValidator(schemes);

        // Add http:// if protocol is missing
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url; //if it is missing I insert it as "http://"
        }

        return urlValidator.isValid(url);
    }

    private static boolean isValidIP(String url) {
        try {
            // Remove the protocol and path to get only the host
            java.net.URL netUrl = new java.net.URL(url.startsWith("http") ? url : "http://" + url);
            String host = netUrl.getHost();

            // Regex for IPv4
            String ipPattern = "^(?:\\d{1,3}\\.){3}\\d{1,3}$";
            Pattern pattern = Pattern.compile(ipPattern);
            Matcher matcher = pattern.matcher(host);

            return matcher.matches();
        } catch (Exception e) {
            return false; // In case of invalid URL
        }
    }

    //check for homographic attack
    private static boolean containsNonASCIICharacters(String domain) {
        return !Charset.forName("US-ASCII").newEncoder().canEncode(domain);
    }

    private void analyzeUrl(String url, MailData mailData) {
        if (isValidIP(url)) {
            mailData.setContainsIpAsUrl(true);
            return;
        }

        try {
            if (isValidURL(url)) {
                mailData.setLink(url);
                if (containsNonASCIICharacters(url)) {
                    mailData.setContainsNonAsciiChars(true);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getEmailText() {
        return emailText;
    }

    public void setEmailText(String emailText) {
        this.emailText = emailText;
    }
}
