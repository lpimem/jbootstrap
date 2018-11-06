package edu.memphis.homesec.bootstrap;

import edu.memphis.homesec.bootstrap.detail.OwnerImplDetail;

public class OwnerImpl implements Owner {

  @Override
  public void start(Configuration config, OnSuccess onSuccess, OnFail onFail)
      throws BootstrapException {
    new OwnerImplDetail().bootstrap(config, new Session(), onSuccess, onFail);
  }


}
