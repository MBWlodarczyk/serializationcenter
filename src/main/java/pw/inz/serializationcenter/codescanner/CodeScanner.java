package pw.inz.serializationcenter.codescanner;

import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;

public class CodeScanner {

    public void setProgress(int progress) {
        this.progress = progress;
    }

    private int progress = 0;

        public void store(MultipartFile file){
            try {
                file.transferTo(new File(System.getProperty("user.dir") + "\\libs\\temp"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        public void invoke(){
            Process proc;
            ProcessBuilder pb = new ProcessBuilder("java", "-jar", System.getProperty("user.dir") + "\\libs\\gadget-inspector-all.jar",  System.getProperty("user.dir") + "\\libs\\temp");
            try {
                proc = pb.start();
                BufferedReader stdInput = new BufferedReader(new
                        InputStreamReader(proc.getInputStream()));
                BufferedReader stdError = new BufferedReader(new
                        InputStreamReader(proc.getErrorStream()));
                String s = null;
                while ((s = stdInput.readLine()) != null) {
                    if(s.contains("Running method discovery..")) setProgress(10);
                    if(s.contains("Analyzing methods for passthrough dataflow...")) setProgress(20);
                    if(s.contains("Performing topological sort...")) setProgress(35);
                    if(s.contains("Analyzing methods in order to build a call graph...")) setProgress(45);
                    if(s.contains("Discovering gadget chain source methods...")) setProgress(65);
                    if(s.contains("Searching call graph for gadget chains...")) setProgress(85);
                    if(s.contains("Iteration 5000, Search space: 1148")) setProgress(90);
                    if(s.contains("[INFO] Found")) setProgress(100);
                    System.out.println(s);
                }
                while ((s = stdError.readLine()) != null) {
                    System.out.println(s);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public String readResult(){

            try {

                return Files.readString(Path.of(System.getProperty("user.dir") + "\\libs\\gadget-chains.txt"), Charset.defaultCharset());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

    public int getProgress() {
        return progress;
    }
}
