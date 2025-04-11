package controller;

import model.MailData;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.ahocorasick.trie.Emit;
import org.ahocorasick.trie.Trie;
import org.apache.tika.language.detect.LanguageDetector;
import org.apache.tika.language.detect.LanguageResult;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class SpamDetectorFromJson {
    private static final String SPAMWORDSITA = System.getenv("app.spam.words.it") != null ? System.getenv("app.spam.words.it") : "src/main/resources/dataset/spamWords/it.json";
    private static final String SPAMWORDSENG = System.getenv("app.spam.words.en") != null ? System.getenv("app.spam.words.en") : "src/main/resources/dataset/spamWords/it.json";

    private String emailText;

    public SpamDetectorFromJson(String emailText) {
        this.emailText = emailText;
    }

    public void findSpamWord(MailData mailData) throws IOException {
        String detectedLanguage = detectLanguage(this.emailText);

        String jsonFile = detectedLanguage.equals("it") ? SPAMWORDSITA : SPAMWORDSENG;

        List<String> keyword = loadKeywordsFromJson(jsonFile);

        Trie.TrieBuilder trieBuilder = Trie.builder().ignoreCase().onlyWholeWords();
        for (String word : keyword) {
            trieBuilder.addKeyword(word);
        }

        Trie trie = trieBuilder.build();
        boolean containsSpam = containsSpamWord(trie, emailText);

        if(containsSpam) {
            mailData.setContainsSpam(true);
        }

    }


    private static boolean containsSpamWord(Trie trie, String emailText) {
        for (Emit match : trie.parseText(emailText)) {
            return true; // As soon as we find a keyword, we return true
        }
        return false;
    }

    private static List<String> loadKeywordsFromJson(String filePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(new File(filePath), List.class);
    }

    private static String detectLanguage(String emailText) throws IOException {
        LanguageDetector languageDetector = LanguageDetector.getDefaultLanguageDetector();
        languageDetector.loadModels();
        LanguageResult result = languageDetector.detect(emailText);
        return result.getLanguage();
    }

}