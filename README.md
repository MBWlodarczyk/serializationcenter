# Serialization Center

This tool aim is to make better use of tools used in java deserialization vulnerability research and pentesting by connecting then all together in one place.

This tool consists of:
* WebScanner - scanning endpoint for known vulnerabilities (based on Java-Deserialization-Scanner)                       
* PayloadGenerator - generating payloads of known vulnerabilities (based on ysoserial)
* PayloadEditor - editing and viewing serialized object in binary form (based on SerializationDumper)                         
* CodeScanner - scanning of jars/wars for potential malicious chains (based on GadgetInspector)
* ClassProbe - identifying classes present on remote classpath (based on GadgetProbe)
