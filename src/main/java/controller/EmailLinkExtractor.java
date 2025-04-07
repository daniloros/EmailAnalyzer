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
            // Analizza gli URL pre-estratti
            for (String url : preExtractedUrls) {
                analyzeUrl(url, mailData);
            }
        }
        //estrai il link dal testo
        findLinkInText(emailText, mailData);
    }


    private static void findLinkInText(String text, MailData mailData) {
//        String urlRegex = "\\b((http(s)?://)?(www\\.)?[a-zA-Z0-9-]+(\\.[a-zA-Z]{2,})+(:\\d+)?(/[\\w\\-\\.~:/?#\\[\\]@!$&'()*+,;=%]*)?)\\b";
        //TODO: VALUTARE QUALE REGEX E' MIGLIORE
        String urlRegex = "(https?://|www\\.)([-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6})\\b[-a-zA-Z0-9()@:%_+.~#?&/=\\-]*";

        Pattern pattern = Pattern.compile(urlRegex);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String originalUrl = matcher.group();

            // Se il link è un IP, verifichiamo con il metodo isValidIP
            if (isValidIP(originalUrl)) {
//                System.out.println("Indirizzo IP valido trovato: " + originalUrl);
                mailData.setContainsIpAsUrl(true);
                continue;
            }


            try {
                if (isValidURL(originalUrl)) {
//                    System.out.println("l'url è valido: " + originalUrl);
                    mailData.setLink(originalUrl);
                    if (containsNonASCIICharacters(originalUrl)) {
//                        System.out.println("ATTENZIONE, l'url contiene caratteri sospetti");
//                        mailData.addSuspiciousUrl(originalUrl);
                        mailData.setContainsNonAsciiChars(true);
                    }
                } else {
//                    System.out.println("l'url non è valido: " + originalUrl);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
    }

    private static boolean isValidURL(String url) {
        // Abilita http e https
        String[] schemes = {"http", "https"};
        UrlValidator urlValidator = new UrlValidator(schemes);

        // Aggiungi http:// se manca il protocollo
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url; // se manca lo inserisco come  "http://"
        }

        return urlValidator.isValid(url);
    }

    private static boolean isValidIP(String url) {
        try {
            // Rimuove il protocollo e il percorso per ottenere solo l'host
            java.net.URL netUrl = new java.net.URL(url.startsWith("http") ? url : "http://" + url);
            String host = netUrl.getHost();

            // Regex per IPv4
            String ipPattern = "^(?:\\d{1,3}\\.){3}\\d{1,3}$";
            Pattern pattern = Pattern.compile(ipPattern);
            Matcher matcher = pattern.matcher(host);

            return matcher.matches();
        } catch (Exception e) {
            return false; // In caso di URL non valido
        }
    }

    //controllo per attacco omografico
    // ritorna true se trova caratteri strani
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
