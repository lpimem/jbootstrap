package edu.memphis.homesec.bootstrap;

import net.named_data.jndn.Name;

public class DefaultDeviceNameGenerator implements DeviceNameGenerator {
    @Override
    public Name generate(String deviceId) {
        Name d = new Name(Owner.DEFAULT_PREFIX);
        d.append("device");
        d.append(deviceId);
        return d;
    }
}
