package edu.memphis.homesec.bootstrap;

import net.named_data.jndn.security.certificate.Certificate;

public class Session {
    Certificate deviceCertificate;
    String challengeToOwner;
    String challengeToDevice;

    public Certificate getDeviceCertificate() {
        return deviceCertificate;
    }

    public void setDeviceCertificate(Certificate deviceCertificate) {
        this.deviceCertificate = deviceCertificate;
    }

    public String getChallengeToOwner() {
        return challengeToOwner;
    }

    public void setChallengeToOwner(String challengeToOwner) {
        this.challengeToOwner = challengeToOwner;
    }

    public String getChallengeToDevice() {
        return challengeToDevice;
    }

    public void setChallengeToDevice(String challengeToDevice) {
        this.challengeToDevice = challengeToDevice;
    }
}
