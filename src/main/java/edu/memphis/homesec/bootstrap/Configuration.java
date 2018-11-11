package edu.memphis.homesec.bootstrap;

import com.google.common.base.Strings;
import edu.memphis.cs.netlab.nacapp.NACNode;
import net.named_data.jndn.security.KeyChain;

public class Configuration {
    private String devicePairingId;
    private String devicePairingCode;
    private DeviceNameGenerator nameGenerator;
    private KeyChain ndnKeyChain;
    private NACNode node;

    public void validate() throws IllegalStateException {
        StringBuilder message = new StringBuilder();
        if (Strings.isNullOrEmpty(devicePairingCode)) {
            message.append("missing device pairing code; ");
        }
        if (Strings.isNullOrEmpty(devicePairingId)){
            message.append("missing device pairing id; ");
        }
        if (null == ndnKeyChain){
            message.append("missing ndnKeyChain; ");
        }
        if (null == nameGenerator){
            System.out.println("WARN: missing name generator, using default.");
            nameGenerator = new DefaultDeviceNameGenerator();
        }
        if (null == node){
            message.append("missing node; ");
        }

        if (message.length() > 0 ){
            throw new IllegalStateException(message.toString());
        }
    }

    public Configuration() {
    }

    public Configuration(Configuration copy){
        this.devicePairingId = copy.devicePairingId;
        this.devicePairingId = copy.devicePairingId;
        this.nameGenerator = copy.nameGenerator;
        this.ndnKeyChain = copy.ndnKeyChain;
        this.node = copy.node;
    }

    public Configuration(String devicePairingId, String devicePairingCode,
                         DeviceNameGenerator nameGenerator, KeyChain ndnKeyChain,
                         NACNode node) {
        this.devicePairingId = devicePairingId;
        this.devicePairingCode = devicePairingCode;
        this.nameGenerator = nameGenerator;
        this.ndnKeyChain = ndnKeyChain;
        this.node = node;
        validate();
    }

    public String getDevicePairingId() {
        return devicePairingId;
    }

    public void setDevicePairingId(String devicePairingId) {
        this.devicePairingId = devicePairingId;
    }

    public String getDevicePairingCode() {
        return devicePairingCode;
    }

    public void setDevicePairingCode(String devicePairingCode) {
        this.devicePairingCode = devicePairingCode;
    }

    public DeviceNameGenerator getNameGenerator() {
        return nameGenerator;
    }

    public void setNameGenerator(DeviceNameGenerator nameGenerator) {
        this.nameGenerator = nameGenerator;
    }

    public KeyChain getNdnKeyChain() {
        return ndnKeyChain;
    }

    public void setNdnKeyChain(KeyChain ndnKeyChain) {
        this.ndnKeyChain = ndnKeyChain;
    }

    public NACNode getNode() {
        return node;
    }

    public void setNode(NACNode node) {
        this.node = node;
    }
}
