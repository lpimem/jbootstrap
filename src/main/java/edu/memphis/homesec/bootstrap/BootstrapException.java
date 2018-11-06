package edu.memphis.homesec.bootstrap;

public class BootstrapException extends Exception {

  private static final long serialVersionUID = 0L;

  public BootstrapException() { super(); }

  public BootstrapException(String message) { super(message); }

  public BootstrapException(Throwable e) { super(e); }
}