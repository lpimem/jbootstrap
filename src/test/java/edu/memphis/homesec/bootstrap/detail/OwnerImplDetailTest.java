package edu.memphis.homesec.bootstrap.detail;

import edu.memphis.cs.netlab.nacapp.KeyChainHelper;
import edu.memphis.cs.netlab.nacapp.NACNode;
import edu.memphis.homesec.bootstrap.BootstrapException;
import edu.memphis.homesec.bootstrap.Configuration;
import edu.memphis.homesec.bootstrap.DefaultDeviceNameGenerator;
import edu.memphis.homesec.bootstrap.OwnerImpl;
import net.named_data.jndn.*;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;

public class OwnerImplDetailTest extends OwnerImplDetail {

    static class LocalTestFace extends Face {
        @Override
        public long expressInterest(Interest interest, OnData onData, OnTimeout onTimeout,
                                    OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException {

            return 0;
        }
    }

    private static Face testFace;
    private static Configuration fixCfg;

    @BeforeClass
    public static void setup() throws SecurityException {
        final Name ownerIdentityName = new Name(OwnerImpl.DEFAULT_PREFIX + "/owner");
        KeyChain keyChain = KeyChainHelper.makeKeyChain(ownerIdentityName, testFace);
        testFace = new LocalTestFace();
        fixCfg = new Configuration();

        fixCfg.setDevicePairingId("TestDevice123");
        fixCfg.setDevicePairingCode("Unsafe54321");
        fixCfg.setNameGenerator(new DefaultDeviceNameGenerator());

        fixCfg.setNdnKeyChain(keyChain);

        NACNode nacNode = new NACNode(new Name(OwnerImpl.DEFAULT_PREFIX), ownerIdentityName, testFace, keyChain);
        fixCfg.setNode(nacNode);
    }

    @Test
    public void testBootstrap() {

    }


    @Test
    public void testParseInitiateInterest() throws BootstrapException {
        final String random = "xxqBJDsy5KyvZoxmiGFS0hOWcrjR1JwxsqYwHH6Y7UM";
        // HMAC SHA256 for "TestDevice123|xxqBJDsy5KyvZoxmiGFS0hOWcrjR1JwxsqYwHH6Y7UM"
        // Key: Unsafe54321
        final String hash = "241afe830f7dde03fcd2aacc4c83b5e654827231b161e5c9d7edb5aced2ddcea";
        final String name = String.format("%s/cert/%s/%s/%s",
                OwnerImpl.DEFAULT_OWNER_BT_PREFIX,
                fixCfg.getDevicePairingId(),
                random,
                hash);
        Interest interest = new Interest(
                new Name(name)
        );

        String[] parts = parseInitiateInterest(interest);
        Assert.assertEquals(parts.length, 3);
        final String devId = parts[0];
        final String r0 = parts[1];
        final String sig = parts[2];

        Assert.assertEquals(devId, fixCfg.getDevicePairingId());
        Assert.assertEquals(r0, random);
        Assert.assertEquals(sig, hash);
    }
}