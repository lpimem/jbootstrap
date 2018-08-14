package edu.memphis.homesec.bootstrap.detail;

import edu.memphis.cs.netlab.nacapp.NACNode;
import edu.memphis.homesec.bootstrap.Configuration;
import edu.memphis.homesec.bootstrap.Owner;
import edu.memphis.homesec.bootstrap.Session;
import net.named_data.jndn.*;

import java.security.cert.Certificate;

public class OwnerImplDetail {
    final private String btOwnerCertName = "/local-home/bootstrap/owner/cert";

    public void bootstrap(Configuration configuration, Session session, Owner.OnSuccess onSuccess, Owner.OnFail onFail){
        final NACNode node = configuration.getNode();

        OnInterestCallback callback = (prefix, interest, face, interestFilterId, filter) -> {
            if (!examineInitiateInterest(interest, configuration)){
                onFail.onFail(configuration.getDevicePairingId(), "Invalid interest for getting owner certificate");
                return;
            }

            sendOwnerCert(interest, configuration, session);

            OnData onDeviceCert = (interest1, data) -> {
                Session s = parseDeviceCert(data, configuration, session);
                serveSignedDeviceCert(s, onSuccess, onFail);
            };

            queryDeviceCertificate(configuration, onDeviceCert, onFail);
        };

        OnRegisterSuccess onRegisterSuccess = (prefix, registeredPrefixId) -> System.out.println(
                String.format("%s registered at %d", prefix.toUri(), registeredPrefixId));

        node.registerPrefix(btOwnerCertName, callback, onRegisterSuccess);
    }

    public boolean examineInitiateInterest(Interest interest, Configuration config){
        return false;
    }

    public void sendOwnerCert(Interest interest, Configuration config, Session session){

    }

    public void queryDeviceCertificate(Configuration config, OnData onData, Owner.OnFail onFail){

    }

    public Session parseDeviceCert(Data d, Configuration c, Session session){
        return session;
    }

    public Certificate signDeviceCertificate(Configuration config, Certificate device){
        return device;
    }

    public void serveSignedDeviceCert(Session session, Owner.OnSuccess onSuccess, Owner.OnFail onFail){


    }

}
