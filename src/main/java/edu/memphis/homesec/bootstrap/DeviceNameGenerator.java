package edu.memphis.homesec.bootstrap;

import net.named_data.jndn.Name;

public interface DeviceNameGenerator {
    Name generate(String deviceId);
}
