package pw.inz.serializationcenter.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import pw.inz.serializationcenter.codescanner.CodeScanner;
import pw.inz.serializationcenter.payloadeditor.SerializationDumper;
import pw.inz.serializationcenter.payloadgenerator.ysoserialPassThru;
import pw.inz.serializationcenter.webscanner.WebScanner;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Controller
@EnableAsync
public class MainController {
    private final SerializationDumper sd;
    private final ysoserialPassThru ysoserialPass;
    private final WebScanner webScanner;
    private final CodeScanner codeScanner;

    @Value("${spring.application.name}")
    String appName;
    String desString;

    byte[] payload;
    String gadgets;
    String scanResult;

    @Autowired
    public MainController() {
        codeScanner = new CodeScanner();
        sd = new SerializationDumper();
        ysoserialPass = new ysoserialPassThru();
        webScanner = new WebScanner();
    }

/* example
AC ED 00 05 73 72 00 0A 53 65 72 69 61 6C 54 65
73 74 A0 0C 34 00 FE B1 DD F9 02 00 02 42 00 05
63 6F 75 6E 74 42 00 07 76 65 72 73 69 6F 6E 78
70 00 64
*/



    @RequestMapping("/index.html")
    public String homePage(Model model) {
        model.addAttribute("appName", appName);
        return "cover";
    }

    @RequestMapping("/status")
    @ResponseBody
    public String getStatus(Model model) {
        return String.valueOf(codeScanner.getProgress());
    }


    @PostMapping("/codescanner/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                                      RedirectAttributes redirectAttributes) {

        codeScanner.store(file);
        codeScanner.invoke();
        gadgets = codeScanner.readResult();
        redirectAttributes.addFlashAttribute("message",
                "You successfully uploaded " + file.getOriginalFilename() + "!");
        return "redirect:/codescanner.html";
    }

    @RequestMapping("/codescanner.html")
    public String codeScanner(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("gadgets",gadgets);
        return "CodeScanner";
    }
    @RequestMapping("/webscanner.html")
    public String webScanner(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("scanResult", scanResult);
        return "WebScanner";
    }
    @RequestMapping("/webscanner/send")
    public String webScannerSend(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("scanResult", scanResult);
        return "WebScanner";
    }

    @PostMapping(path = "/webscanner/scan", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String  scanURL(@RequestParam String url,@RequestParam String request)  {
        if(payload == null) {
            scanResult = webScanner.doScan(url, request);
            System.out.println(scanResult);
            return "redirect:/webscanner.html";
        } else {
            webScanner.sendPayload(url,request,payload);
            scanResult = "Send successfully...";
            payload = null;
            return "redirect:/webscanner.html";
        }
    }


    @RequestMapping("/payloadgenerator.html")
    public String payloadGenerator(Model model) {
        model.addAttribute("possible_payloads",ysoserialPass.getPayloads());
        model.addAttribute("appName", appName);
        return "PayloadGenerator";
    }

    @PostMapping(path = "/payloadgenerator/generate", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String generatePayload(@RequestParam String payloadname, @RequestParam String payloadcmd,
                                  @RequestParam String action, ModelMap model, HttpServletResponse response) throws Exception {
        if(action.equals("submit")) {
            byte[] a = ysoserialPass.invoke(payloadname, payloadcmd);
            response.getOutputStream().write(a);
            response.setHeader("Content-disposition", "attachment; filename=payload_" + payloadname + payloadcmd);
            response.getOutputStream().flush();
        }
        else if(action.equals("send")){
            payload = ysoserialPass.invoke(payloadname, payloadcmd);
            return  "redirect:/webscanner/send";
        }

        return  null;
    }

    @GetMapping("/payloadeditor.html")
    public String payloadEditor(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("desString", desString);
        return "PayloadEditor";
    }

    @PostMapping(path = "/payloadeditor.html", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String printPayload(@RequestParam String payload,@RequestParam String action,
                               ModelMap model) throws Exception {
        if(action.equals("print")) {
            desString = sd.main(new String[]{payload});
            model.addAttribute("desString", desString);
            return "redirect:/payloadeditor.html";
        } else if (action.equals("send")){
            this.payload = sd.hexStrToBytes(payload.replaceAll("[\s\r\n]", "").toUpperCase());
            return "redirect:/webscanner.html";
        }
        return null;
    }

    @PostMapping(path = "/payloadeditor/save", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String savePayload(@RequestParam String name,
                               ModelMap model) throws Exception {
        sd.store(name,desString);
        return "redirect:/payloadeditor.html";
    }

    @PostMapping(path = "/payloadeditor/edit", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String printPayload(@RequestParam Map<String, String> params,
                               ModelMap model) throws Exception {

        desString = sd.changeValues(this.desString, params);
        return "redirect:/payloadeditor.html";
    }

    @GetMapping(path = "/payloadeditor/download", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public @ResponseBody
    void serveAsFile(ModelMap model, HttpServletResponse response) throws IOException {
        if (desString != null) sd.rebuildStream(desString);
        response.setHeader("Content-disposition", "attachment; filename=edited_payload");
        response.getOutputStream().write(sd.get_data());
        response.getOutputStream().flush();
    }


}
