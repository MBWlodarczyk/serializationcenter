package pw.inz.serializationcenter.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import pw.inz.serializationcenter.payloadeditor.SerializationDumper;
import pw.inz.serializationcenter.payloadgenerator.ysoserialPassThru;




import java.util.Map;

@Controller
public class MainController {
    @Value("${spring.application.name}")
    String appName;

    String desString;

    String bytesString;

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

    @RequestMapping("/payloadgenerator.html")
    public String payloadGenerator(Model model) {
        model.addAttribute("appName", appName);
        return "PayloadGenerator";
    }

    @PostMapping(path ="/payloadgenerator/generate",consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String generatePayload(@RequestParam String payloadname,@RequestParam String payloadcmd,
                               ModelMap model) throws Exception {
        byte[] a = ysoserialPassThru.invoke(payloadname,payloadcmd);
        System.out.println(new String(a));
        return "redirect:/payloadgenerator.html";
    }

    @GetMapping("/payloadeditor.html")
    public String payloadEditor(Model model) {
        model.addAttribute("appName", appName);
        model.addAttribute("desString",desString);
        model.addAttribute("byteString",bytesString);
        return "PayloadEditor";
    }
    @PostMapping(path ="/payloadeditor.html",consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String printPayload(@RequestParam String payload,
                                ModelMap model) throws Exception {
        SerializationDumper sd = new SerializationDumper();
        desString = sd.main(new String[]{payload});
        bytesString = payload;
        model.addAttribute("byteString",bytesString);
        model.addAttribute("desString",desString);
        return "redirect:/payloadeditor.html";
    }

    @PostMapping(path ="/payloadeditor/edit",consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String printPayload(@RequestParam Map<String, String> params,
                               ModelMap model) throws Exception {
        SerializationDumper sd = new SerializationDumper();
        desString = sd.changeValues(this.desString,params);
        return "redirect:/payloadeditor.html";
    }

    @GetMapping(path="/payloadeditor/download",produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public @ResponseBody
    byte[] serveAsFile(ModelMap model) {
        SerializationDumper sd = new SerializationDumper();
        if(desString!=null) sd.rebuildStream(desString);
        return sd.get_data();
    }


}
