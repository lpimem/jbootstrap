package edu.memphis.homesec.bootstrap.detail;

import edu.memphis.cs.netlab.nacapp.NACNode;
import edu.memphis.homesec.bootstrap.BootstrapException;
import edu.memphis.homesec.bootstrap.Configuration;
import edu.memphis.homesec.bootstrap.Owner;
import edu.memphis.homesec.bootstrap.Session;
import net.named_data.jndn.*;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class OwnerImplDetail {

  private final static Logger logger =
      Logger.getLogger(OwnerImplDetail.class.getName());

  final private String btOwnerCertName = "/local-home/bootstrap/owner/cert";

  public void bootstrap(Configuration configuration, Session session,
                        Owner.OnSuccess onSuccess, Owner.OnFail onFail)
      throws BootstrapException {
    final NACNode node = configuration.getNode();

    OnInterestCallback callback =
        (prefix, interest, face, interestFilterId, filter) -> {
      try {
        if (!examineInitiateInterest(interest, configuration)) {
          onFail.onFail(configuration.getDevicePairingId(),
                        "Invalid interest for getting owner certificate");
          return;
        }
      } catch (BootstrapException e1) {
        onFail.onFail(configuration.getDevicePairingId(), e1.getMessage());
      }

      try {
        sendOwnerCert(interest, configuration, session);
      } catch (BootstrapException e) {
        logger.warning("Cannot send owner cert.");
        onFail.onFail(configuration.getDevicePairingId(), e.getMessage());
      }

      OnData onDeviceCert = (interest1, data) -> {
        Session s = parseDeviceCert(data, configuration, session);
        serveSignedDeviceCert(configuration, s, onSuccess, onFail);
      };

      try {
        queryDeviceCertificate(configuration, onDeviceCert, onFail);
      } catch (BootstrapException e) {
        logger.warning("Cannot query device cert.");
        onFail.onFail(configuration.getDevicePairingId(), e.getMessage());
      }
    };

    OnRegisterSuccess onRegisterSuccess = (prefix, registeredPrefixId)
        -> logger.info(String.format("%s registered at %d", prefix.toUri(),
                                     registeredPrefixId));

    node.registerPrefix(btOwnerCertName, callback, onRegisterSuccess);
  }

  private String[] parseInitiateInterest(Interest interest) {
    // TODO : implement
    return null;
  }

  public static String toHex(byte[] bytes) {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
  }

  /*
   * from: http://www.java2s.com/Code/Java/Data-Type/hexStringToByteArray.htm
   */
  public static byte[] fromHex(String hex) {
    byte[] b = new byte[hex.length() / 2];
    for (int i = 0; i < b.length; i++) {
      int index = i * 2;
      int v = Integer.parseInt(hex.substring(index, index + 2), 16);
      b[i] = (byte)v;
    }
    return b;
  }

  private byte[] hmac(byte[] input, byte[] key) throws BootstrapException {
    Mac mac;
    try {
      mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
      mac.init(keySpec);
      return mac.doFinal(input);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      logger.severe("Cannot calculate hmac" + e.getMessage());
      throw new BootstrapException(e.getMessage());
    }
  }

  private String hmac(String input, String key) throws BootstrapException {
    byte[] hash = hmac(input.getBytes(), fromHex(key));
    return toHex(hash); }

  public boolean examineInitiateInterest(Interest interest,
                                         Configuration config)
      throws BootstrapException {
    String[] values = parseInitiateInterest(interest);
    final String devId = values[0];
    final String r0 = values[1];
    final String hmac = values[2];
    final String input = String.format("%s|%s", devId, r0);
    // TODO: Secure compare.
    return hmac(input, config.getDevicePairingCode()).equalsIgnoreCase(hmac);
  }

  public void sendOwnerCert(Interest interest, Configuration config,
                            Session session) throws BootstrapException {
    final KeyChain keychain = config.getNdnKeyChain();
    final NACNode node = config.getNode();
    try {
      IdentityCertificate c =
          keychain.getCertificate(keychain.getDefaultCertificateName());
      node.putData(c);
    } catch (DerDecodingException | SecurityException e) {
      logger.warning("Cannot get owner identity " + e.getMessage());
      throw new BootstrapException(e);
    }
  }

  public void queryDeviceCertificate(Configuration config, OnData onData,
                                     Owner.OnFail onFail)
      throws BootstrapException {
    final int retry = 5;
    Interest i = makeDeviceCertificateInterest(config.getDevicePairingId());
    OnNetworkNack onNack = new OnNetworkNack() {
      @Override
      public void onNetworkNack(Interest interest, NetworkNack networkNack) {
        onFail.onFail(config.getDevicePairingId(),
                      networkNack.getReason().name());
      }
    };
    try {
      config.getNode().expressInterest(i, onData, onNack, retry);
    } catch (IOException e) {
      throw new BootstrapException(e);
    }
  }

  private Interest makeDeviceCertificateInterest(String devicePairingId) {
    return null;
  }

  public Session parseDeviceCert(Data d, Configuration c, Session session) {
    return session;
  }

  public Certificate signDeviceCertificate(Configuration config,
                                           Certificate device) {
    return device;
  }

  public void serveSignedDeviceCert(Configuration config, Session session,
                                    Owner.OnSuccess onSuccess,
                                    Owner.OnFail onFail) {

    final NACNode node = config.getNode();

    Name prefix = makeSignedCertificateName(config.getDevicePairingId());

    OnInterestCallback onInterestCallback = new OnInterestCallback() {
      @Override
      public void onInterest(Name prefix, Interest interest, Face face,
                             long interestFilterId, InterestFilter filter) {
        node.putData(session.getDeviceCertificate());
        onSuccess.onSuccess(config.getDevicePairingId());
      }
    };

    OnRegisterFailed onRegisterFailed = new OnRegisterFailed() {
      @Override
      public void onRegisterFailed(Name prefix) {
        onFail.onFail(config.getDevicePairingId(),
                      "Cannot serve device cert: cannot register prefix");
      }
    };

    OnRegisterSuccess onRegisterSuccess = new OnRegisterSuccess() {
      @Override
      public void onRegisterSuccess(Name prefix, long registeredPrefixId) {
        logger.fine("Registered prefix " + prefix.toUri());
      }
    };

    config.getNode().registerPrefix(prefix, onInterestCallback,
                                    onRegisterFailed, onRegisterSuccess, 5);
  }

  private Name makeSignedCertificateName(String devicePairingId) {
    // TODO
    return null;
  }
}
