package edu.memphis.homesec.bootstrap.detail;

import edu.memphis.cs.netlab.nacapp.Global;
import edu.memphis.cs.netlab.nacapp.NACNode;
import edu.memphis.homesec.bootstrap.BootstrapException;
import edu.memphis.homesec.bootstrap.Configuration;
import edu.memphis.homesec.bootstrap.Owner;
import edu.memphis.homesec.bootstrap.Session;
import net.named_data.jndn.*;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.Certificate;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.tpm.TpmBackEnd.Error;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OwnerImplDetail {

  private final static Logger logger =
      LoggerFactory.getLogger(OwnerImplDetail.class);

  private final Name btOwnerCertName =
      new Name(Owner.DEFAULT_OWNER_BT_PREFIX + "/cert");

  public void bootstrap(Configuration configuration, Session session,
                        Owner.OnSuccess onSuccess, Owner.OnFail onFail)
      throws BootstrapException {
    final NACNode node = configuration.getNode();

    OnInterestCallback callback =
        (prefix, interest, face, interestFilterId, filter) -> {
      try {
        if (!examineInitiateInterest(interest, configuration, session)) {
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
        logger.warn("Cannot send owner cert.");
        onFail.onFail(configuration.getDevicePairingId(), e.getMessage());
      }

      OnData onDeviceCert = (interest1, data) -> {
        Session s = null;
        try {
          s = parseDeviceCert(data, configuration, session);
        } catch (BootstrapException e) {
          onFail.onFail(configuration.getDevicePairingId(), e.getMessage());
          return;
        }
        serveSignedDeviceCert(configuration, s, onSuccess, onFail);
      };

      try {
        queryDeviceCertificate(configuration, session, onDeviceCert, onFail);
      } catch (BootstrapException e) {
        logger.warn("Cannot query device cert.");
        onFail.onFail(configuration.getDevicePairingId(), e.getMessage());
      }
    };

    OnRegisterSuccess onRegisterSuccess = (prefix, registeredPrefixId)
        -> logger.info(String.format("%s registered at %d", prefix.toUri(),
                                     registeredPrefixId));

    node.registerPrefix(btOwnerCertName, callback, onRegisterSuccess);
  }

  private String[] parseInitiateInterest(Interest interest)
      throws BootstrapException {
    logger.debug("parsing interest {}", interest.getName());
    final int i = btOwnerCertName.size();
    final int min_length = i + 2;
    if (interest.getName().size() <= min_length) {
      throw new BootstrapException("Format error: interest name is too short.");
    }
    String pairingId = interest.getName().get(i).toString();
    String r0 = interest.getName().get(i + 1).toString();
    String hmac = interest.getName().get(i + 2).toString();
    logger.debug("parsed: Device Pairing ID: {}, R: {}, HMAC: {}", pairingId,
                 r0, hmac);
    return new String[] {pairingId, r0, hmac};
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
      logger.error("Cannot calculate hmac" + e.getMessage());
      throw new BootstrapException(e.getMessage());
    }
  }

  private String hmac(String input, String key) throws BootstrapException {
    byte[] hash = hmac(input.getBytes(), fromHex(key));
    return toHex(hash);
  }

  public boolean examineInitiateInterest(Interest interest,
                                         Configuration config,
                                         Session s)
      throws BootstrapException {
    String[] values = parseInitiateInterest(interest);
    final String devId = values[0];
    final String r0 = values[1];
    final String sig = values[2];
    final String input = String.format("%s|%s", devId, r0);
    final String hmacHash = hmac(input, config.getDevicePairingCode());
    final boolean match = secureCompare(sig, hmacHash);
    if (match) {
      s.setChallengeToOwner(r0);
    }
    return match;
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
      logger.warn("Cannot get owner identity " + e.getMessage());
      throw new BootstrapException(e);
    }
  }

  public void queryDeviceCertificate(Configuration config, Session session,
                                     OnData onData, Owner.OnFail onFail)
      throws BootstrapException {
    final int retry = 5;
    Interest i = makeDeviceCertificateInterest(config, session);
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

  private Interest makeDeviceCertificateInterest(Configuration c, Session s)
      throws BootstrapException {
    Name n = new Name(Owner.DEFAULT_BOOTSTRAP_PREFIX);
    n.append("device");
    n.append(c.getDevicePairingId());
    n.append(s.getChallengeToOwner());

    final String challengeToDev = randomHexString(7);
    s.setChallengeToDevice(challengeToDev);
    
    n.append(s.getChallengeToDevice());
    String check =
        String.format("%s%s%s", c.getDevicePairingId(), s.getChallengeToOwner(),
                      s.getChallengeToDevice());
    String hmacHash = hmac(check, c.getDevicePairingCode());
    n.append(hmacHash);
    Interest i = new Interest(n, Global.DEFAULT_INTEREST_TIMEOUT_MS);
    return i;
  }

  private boolean secureCompare(String a, String b) {
    // TODO
    return null != a && a.equals(b);
  }

  public Session parseDeviceCert(Data d, Configuration c, Session session)
      throws BootstrapException {
    final String content = getContentAsString(d);
    final String[] parts = content.split("|");
    final String certHex = parts[0];
    final String signature = parts[1];

    final String check =
        String.format("%s%s%s", certHex, session.getChallengeToOwner(),
                      session.getChallengeToDevice());
    final String hmacHash = hmac(check, c.getDevicePairingCode());
    if (!secureCompare(hmacHash, signature)) {
      throw new BootstrapException("Invalid Signature");
    }

    byte[] certBytes = fromHex(certHex);
    ByteBuffer bf = ByteBuffer.wrap(certBytes);
    Data certData = new Data();
    try {
      certData.wireDecode(bf);
    } catch (EncodingException e) {
      logger.error("Cannot re-construct cert data: {}", e.getMessage());
      throw new BootstrapException(e);
    }
    try {
      Certificate cert = new Certificate(certData);
      session.setDeviceCertificate(cert);
    } catch (DerDecodingException e) {
      logger.error("Cannot re-construct cert from data, error: {}", e.getMessage());
      throw new BootstrapException(e);
    }
    return session;
  }

  public Certificate signDeviceCertificate(Configuration config,
                                           Certificate device)
      throws BootstrapException {
    KeyChain keychain = config.getNdnKeyChain();
    try {
      keychain.sign(device);
    } catch (SecurityException | Error |
             net.named_data.jndn.security.pib.PibImpl.Error |
             net.named_data.jndn.security.KeyChain.Error e) {
      logger.error("Cannot sign device cert, {}", e.getMessage());
      throw new BootstrapException(e);
    }
    return device;
  }

  public void serveSignedDeviceCert(Configuration config, Session session,
                                    Owner.OnSuccess onSuccess,
                                    Owner.OnFail onFail) {

    final NACNode node = config.getNode();

    Name prefix = makeSignedCertificateName(config.getDevicePairingId(),
                                            session.getChallengeToOwner());

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
        logger.debug("Registered prefix " + prefix.toUri());
      }
    };

    config.getNode().registerPrefix(prefix, onInterestCallback,
                                    onRegisterFailed, onRegisterSuccess, 5);
  }

  private Name makeSignedCertificateName(String devicePairingId,
                                         String challengeOwner) {
    Name n = new Name(btOwnerCertName);
    n.append("signed-cert");
    n.append(devicePairingId);
    n.append(challengeOwner);
    return n;
  }

  public static String randomHexString(int length){
    Random r = new Random();
    r.setSeed(System.nanoTime());
    byte[] buf = new byte[length];
    r.nextBytes(buf);
    return toHex(buf);
  }

  public static String getContentAsString(Data d) {
    return new String(d.getContent().getImmutableArray());
  }
}
