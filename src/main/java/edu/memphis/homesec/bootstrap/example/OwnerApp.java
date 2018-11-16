package edu.memphis.homesec.bootstrap.example;

import edu.memphis.cs.netlab.nacapp.KeyChainHelper;
import edu.memphis.cs.netlab.nacapp.NACNode;
import edu.memphis.homesec.bootstrap.*;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;

public class OwnerApp {

    public static void main(String[] args) throws SecurityException, BootstrapException {

        final String devicePairingId = "SampleDevice12345";
        final String devicePairingCode = "Unsafe12345";

        Name ownerNameSpace = new Name(Owner.DEFAULT_PREFIX + "/owner");
        Name bootstrapOwnerPrefix = new Name(Owner.DEFAULT_BOOTSTRAP_PREFIX);

        Face f = new Face();
        KeyChain keyChain = KeyChainHelper.makeKeyChain(ownerNameSpace, f);
        NACNode node = new NACNode(bootstrapOwnerPrefix, ownerNameSpace, f, keyChain);

        Configuration bootstrapConfig = new Configuration(
                devicePairingId,
                devicePairingCode,
                new DefaultDeviceNameGenerator(),
                keyChain,
                node);

        Owner owner = new OwnerImpl();

        owner.start(bootstrapConfig,
                devicePairingId1 -> System.out.println("Bootstrap Success"),
                (devicePairingId1, reason) -> System.out.println("FAILED: " + reason));
    }
}
