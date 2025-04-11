package controller;

import model.EmailFromBert;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.google.gson.Gson;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;

@Component
public class BERTEmbeddingClient {
    private static String API_URL;

    @Value("${app.bert.api.url}")
    public void setApiUrl(String url) {
        API_URL = url;
    }

    public BERTEmbeddingClient(String bertApiUrl) {
        API_URL = bertApiUrl;
    }

    public BERTEmbeddingClient() {
    }

    public static EmailFromBert getEmbedding(String emailText) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(API_URL);
            request.setHeader("Content-Type", "application/json");

            // create the JSON payload
            String json = new Gson().toJson(new EmailRequest(emailText));
            request.setEntity(new StringEntity(json, "UTF-8"));

            // Make the request
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String responseBody = EntityUtils.toString(response.getEntity());

                // Check if the answer is valid
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new IOException("Error API: " + response.getStatusLine().getStatusCode() + " - " + responseBody);
                }

                EmailFromBert embeddingResponse = new Gson().fromJson(responseBody, EmailFromBert.class);
                return embeddingResponse;
            }
        }
    }

    // Class for the request
    static class EmailRequest {
        String text;
        EmailRequest(String text) { this.text = text; }
    }

}


