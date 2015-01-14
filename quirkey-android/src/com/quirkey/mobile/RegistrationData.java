package com.quirkey.mobile;

public class RegistrationData {

	private String name;
	private byte[] clientCopyOfServerKey;
	private byte[] clientPrivateKey;
	private byte[] clientPublicKey;

	public RegistrationData() {

	}

	public RegistrationData(String name, byte[] clientCopyOfServerKey,
			byte[] clientPrivateKey, byte[] clientPublicKey) {

		this.name = name;
		this.clientCopyOfServerKey = clientCopyOfServerKey;
		this.clientPrivateKey = clientPrivateKey;
		this.clientPublicKey = clientPublicKey;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public byte[] getClientCopyOfServerKey() {
		return clientCopyOfServerKey;
	}

	public void setClientCopyOfServerKey(byte[] clientCopyOfServerKey) {
		this.clientCopyOfServerKey = clientCopyOfServerKey;
	}

	public byte[] getClientPrivateKey() {
		return clientPrivateKey;
	}

	public void setClientPrivateKey(byte[] clientPrivateKey) {
		this.clientPrivateKey = clientPrivateKey;
	}

	public byte[] getClientPublicKey() {
		return clientPublicKey;
	}

	public void setClientPublicKey(byte[] clientPublicKey) {
		this.clientPublicKey = clientPublicKey;
	}

}
