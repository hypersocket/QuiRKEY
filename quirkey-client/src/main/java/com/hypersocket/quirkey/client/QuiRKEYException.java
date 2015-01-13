package com.hypersocket.quirkey.client;

@SuppressWarnings("serial")
public class QuiRKEYException extends Exception {

	int errorCode;
	public QuiRKEYException(int errorCode, String message) {
		super(message);
		this.errorCode = errorCode;
	}
	
	public int getErrorCode() {
		return errorCode;
	}
}
