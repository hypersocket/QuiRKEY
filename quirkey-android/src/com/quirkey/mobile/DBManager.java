package com.quirkey.mobile;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteOpenHelper;

public class DBManager extends SQLiteOpenHelper {

	// Registration data
	public final class RegistrationTable {
		public static final String TABLE = "REGISTRATION_DATA";
		public static final String NAME = "NAME";
		public static final String SERVER_KEY = "SERVER_KEY";
		public static final String CLIENT_PRIVATE_KEY = "CLIENT_PRIVATE_KEY";
		public static final String CLIENT_PUBLIC_KEY = "CLIENT_PUBLIC_KEY";
		public static final String PASSCODE = "PASSCODE";
	}

	// Creating table Registration data
	private static final StringBuffer SQL_CREATE_REGISTRATION_DATA = new StringBuffer(
			"CREATE TABLE ").append(RegistrationTable.TABLE).append("(")
			.append(RegistrationTable.NAME).append(" ").append(Constants.TEXT)
			.append(", ").append(RegistrationTable.SERVER_KEY).append(" ")
			.append(Constants.BLOB).append(", ")
			.append(RegistrationTable.CLIENT_PRIVATE_KEY).append(" ")
			.append(Constants.BLOB).append(", ")
			.append(RegistrationTable.CLIENT_PUBLIC_KEY).append(" ")
			.append(Constants.BLOB).append(", ").append(RegistrationTable.PASSCODE).append(" ")
			.append(Constants.TEXT).append(")");

	public DBManager(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
	}

	public DBManager(Context context, String name, CursorFactory factory) {
		super(context, name, factory, Constants.BD_LAST_VERSION);
	}

	@Override
	public void onCreate(SQLiteDatabase db) {
		db.execSQL(SQL_CREATE_REGISTRATION_DATA.toString());

	}

	@Override
	public void onUpgrade(SQLiteDatabase db, int previousVersion, int newVersion) {

	}
}