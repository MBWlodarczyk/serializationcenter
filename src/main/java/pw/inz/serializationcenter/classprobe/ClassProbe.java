package pw.inz.serializationcenter.classprobe;
import com.bishopfox.gadgetprobe.GadgetProbe;
public class ClassProbe {

    private GadgetProbe gp;

    public void swapDomain(String domain){
        gp = new GadgetProbe(domain);
    }


    public Object[] makeObj(String [] clazzes){
        Object[] result = new Object[clazzes.length];
        for (int i=0;i< clazzes.length;i++){
            result[i]=gp.getObject(clazzes[i]);
        }
        return result;
    }
    public String[] parseInput(String input){
        return null;
    }

}
