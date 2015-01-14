package com.quirkey.mobile;

public class Constants {
	public static final int SPLASH_DELAY = 3000;
	public static final int CAMERA_REQUEST_CODE = 1;
	public static final int CAMERA_RESULT_CODE = 1;
	public static final String QR_BASE64 = "qr_base64";
	public static final String FILE_NAME = "QiRKEY-client.prv";

	public static final String TEXT = "TEXT";
	public static final String BLOB = "BLOB";

	public static final int BD_LAST_VERSION = 1;
	public static final int TRANSACTION_TYPE_REG = 1;
	public static final int TRANSACTION_TYPE_AUTH = 2;

	public enum RegistrationTableIndexes {

		NAME(0), SERVER_KEY(1), CLIENT_PRIVATE_KEY(2), CLIENT_PUBLIC_KEY(3), PASSCODE(
				4);

		private int registrationTableIndex;

		RegistrationTableIndexes(int registrationTableIndex) {
			this.registrationTableIndex = registrationTableIndex;
		}

		public int getCode() {
			return this.registrationTableIndex;
		}

	}
}
