package pw.inz.serializationcenter.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
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
import java.util.concurrent.CompletableFuture;

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

    @PostMapping(path = "/webscanner/scan", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String  scanURL(@RequestParam String url)  {
        scanResult= webScanner.doScan(url);
        System.out.println(scanResult);
        return "redirect:/webscanner.html";
    }

    @RequestMapping("/payloadgenerator.html")
    public String payloadGenerator(Model model) {
        model.addAttribute("appName", appName);
        return "PayloadGenerator";
    }

    @PostMapping(path = "/payloadgenerator/generate", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public void generatePayload(@RequestParam String payloadname, @RequestParam String payloadcmd,
                                ModelMap model, HttpServletResponse response) throws Exception {
        byte[] a = ysoserialPass.invoke(payloadname, payloadcmd);
        response.getOutputStream().write(a);
        response.setHeader("Content-disposition", "attachment; filename=payload_" + payloadname + payloadcmd);
        response.getOutputStream().flush();

    }

    @GetMapping("/payloadeditor.html")
    public String payloadEditor(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("desString", desString);
        return "PayloadEditor";
    }

    @PostMapping(path = "/payloadeditor.html", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String printPayload(@RequestParam String payload,
                               ModelMap model) throws Exception {
        //SerializationDumper sd = new SerializationDumper();
        desString = sd.main(new String[]{payload});
        model.addAttribute("desString", desString);
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
