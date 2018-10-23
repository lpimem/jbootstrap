package edu.memphis.homesec.bootstrap;

public interface Owner {

    interface  OnSuccess{
        void onSuccess(String devicePairingId);
    }

    interface OnFail{
        void onFail(String devicePairingId, String reason);
    }

    void start(Configuration config, OnSuccess onSuccess, OnFail onFail) throws BootstrapException;

    String DEFAULT_PREFIX = "/local-home";
    String DEFAULT_BOOTSTRAP_PREFIX = DEFAULT_PREFIX + "/bootstrap";
}
