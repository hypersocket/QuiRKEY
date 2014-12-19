package com.quirkey.mobile;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.ConnectivityManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.quirkey.client.ClientAuthenticationTransaction;
import com.hypersocket.quirkey.client.ClientRegistrationTransaction;
import com.hypersocket.quirkey.client.QuiRKEYAuthenticationException;
import com.hypersocket.quirkey.client.QuiRKEYRegistrationException;
import com.quirkey.mobile.R;
import com.quirkey.mobile.DBManager.RegistrationTable;

public class MenuActivity extends Activity {

	private Button buttonScan;

	private KeyPair clientKey;
	private ECCryptoProvider provider = ECCryptoProviderFactory
			.createInstance("secp256r1");
	private ClientRegistrationTransaction registrationClient;
	private ClientAuthenticationTransaction authenticationClient;
	private ProgressDialog dialog;
	private AlertDialog.Builder alertbox;
	private boolean trust = false;
	private Map<String, String> params;
	private SQLiteDatabase db;
	private Cursor cursor;
	private boolean registered = false;

	static {
		Security.insertProviderAt(
				new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_menu);
		Log.i(this.getClass().getName(), "onCreate()");

		DBManager dbManager = new DBManager(this, RegistrationTable.TABLE, null);
		db = dbManager.getWritableDatabase();

		alertbox = new AlertDialog.Builder(this);
		alertbox.setNeutralButton(R.string.ok,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int arg1) {
						// When the user presses "OK" the dialog is
						// closed
						dialog.dismiss();
						Log.i(this.getClass().getName(),
								"alertbox.onClick() - OK");
					}
				});
		buttonScan = (Button) findViewById(R.id.button_scan);
		buttonScan.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				Log.i(this.getClass().getName(), "buttonRegister.onClick()");
				Intent i = new Intent(MenuActivity.this, CameraActivity.class);
				i.putExtra("registered", registered);
				Log.i(this.getClass().getName(),
						"buttonScan.onClick() - Calling CameraActivity.java");
				MenuActivity.this.startActivityForResult(i,
						Constants.CAMERA_REQUEST_CODE);
			}
		});

		String[] fields = new String[] { RegistrationTable.NAME,
				RegistrationTable.SERVER_KEY,
				RegistrationTable.CLIENT_PRIVATE_KEY,
				RegistrationTable.CLIENT_PUBLIC_KEY };
		cursor = db.query(RegistrationTable.TABLE, fields, null, null, null,
				null, null);
		if (cursor.moveToFirst()) {
			changeStatus(true);

		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		Log.i(this.getClass().getName(), "onActivityResult()");
		switch (requestCode) {
		case (Constants.CAMERA_REQUEST_CODE): {
			Log.i(this.getClass().getName(),
					"onActivityResult() - CAMERA_REQUEST_CODE");
			if (resultCode == Activity.RESULT_OK) {
				Log.i(this.getClass().getName(),
						"onActivityResult() - CAMERA_REQUEST_CODE - RESULT_OK");
				final String qrCodeInfo = data.getExtras().getString(
						Constants.QR_BASE64);
				Log.i(this.getClass().getName(),
						"onActivityResult() - registration info = "
								+ qrCodeInfo);
				TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
				params = new HashMap<String, String>();

				params.put("deviceId", telephonyManager.getDeviceId());
				params.put("deviceName", Build.MANUFACTURER + ", "
						+ Build.MODEL);

				try {

					if (registered) {

						authenticationClient = new ClientAuthenticationTransaction(
								qrCodeInfo, "secp256r1");
						new RegisterDeviceSubAsyncTask().execute(params);
					} else {

						clientKey = provider.generateKeyPair();
						registrationClient = new ClientRegistrationTransaction(
								clientKey, qrCodeInfo, "secp256r1");

						if (registrationClient.isPasscode()) {
							Dialog dialogSetPasscode = new Dialog(MenuActivity.this);
							dialogSetPasscode.setContentView(R.layout.set_passcode_layout);
//							dialogSearchLocation.setTitle(this.getResources().getString(
//									R.string.selectCity));
//
//							spinnerProvinces = (Spinner) dialogSearchLocation
//									.findViewById(R.id.spinnerProvince);
//							spinnerCities = (Spinner) dialogSearchLocation
//									.findViewById(R.id.spinnerCity);
//							buttonSearch = (Button) dialogSearchLocation
//									.findViewById(R.id.buttonSearch);
//
//							buttonSearch.setOnClickListener(new OnClickListener() {
//
//								@Override
//								public void onClick(View v) {
//									// Search pressed
//									Log.i(this.getClass().getName(), "buttonSearch.onClick()");
//									Intent i = new Intent(MenuActivity.this,
//											TimetableByLocationActivity.class);
//									i.putExtra("cityName", spinnerCities.getSelectedItem()
//											.toString());
//									Log.i(this.getClass().getName(),
//											"buttonSearch.onClick() - cityName: "
//													+ spinnerCities.getSelectedItem().toString());
//									dialogSearchLocation.dismiss();
//
//									// Calling a new activity
//									MenuActivity.this.startActivity(i);
//
//								}
						} else {
							new RegisterDeviceSubAsyncTask().execute(params);
						}

					}

				} catch (QuiRKEYRegistrationException e) {
					alertbox.setTitle(R.string.transaction_error);
					alertbox.setMessage(R.string.reg_transaction_error);
					alertbox.show();
					return;
				} catch (QuiRKEYAuthenticationException e) {
					alertbox.setTitle(R.string.transaction_error);
					alertbox.setMessage(R.string.auth_transaction_error);
					alertbox.show();
					return;

				} catch (Exception e) {
					Log.i(this.getClass().getName(),
							"onActivityResult() - Error while generating the registration: "
									+ e.getMessage());
				}

			} else if (resultCode == Activity.RESULT_CANCELED) {
				Log.i(this.getClass().getName(),
						"onActivityResult() - CANCELED");

			} else {
				Log.i(this.getClass().getName(), "onActivityResult() - ERROR");
				alertbox.setTitle(R.string.error);
				alertbox.setMessage(R.string.scan_error);
				alertbox.show();
			}
			break;
		}
		}
	}

	class RegisterDeviceSubAsyncTask extends
			AsyncTask<Map<String, String>, Void, String> {

		@Override
		protected void onPreExecute() {
			// While the app waits for the information needed, a progress dialog
			// is
			// shown
			Log.i(this.getClass().getName(),
					"RegisterDeviceSubAsyncTask.onPreExecute()");
			dialog = ProgressDialog.show(MenuActivity.this, "",
					MenuActivity.this.getString(R.string.please_wait), true);
		}

		protected String doInBackground(Map<String, String>... params) {
			Log.i(this.getClass().getName(),
					"RegisterDeviceSubAsyncTask.doInBackground()");

			try {
				String clientRequest;
				HttpPost httpPost;
				if (registered) {

					clientRequest = authenticationClient
							.generateAuthenticationRequest(

									params[0].get("deviceId"),
									params[0].get("deviceName"),
									cursor.getBlob(Constants.RegistrationTableIndexes.SERVER_KEY
											.getCode()),
									cursor.getString(Constants.RegistrationTableIndexes.NAME
											.getCode()),
									cursor.getBlob(Constants.RegistrationTableIndexes.CLIENT_PRIVATE_KEY
											.getCode()),
									cursor.getBlob(Constants.RegistrationTableIndexes.CLIENT_PUBLIC_KEY
											.getCode()));

					httpPost = new HttpPost(authenticationClient.getUrl()
							+ "quirkey/authentication/"
							+ authenticationClient.getAuthenticationId() + "/"
							+ params[0].get("deviceId"));
				} else {
					clientRequest = registrationClient
							.generateRegistrationRequest(
									params[0].get("deviceId"),
									params[0].get("deviceName"));

					httpPost = new HttpPost(registrationClient.getUrl()
							+ "quirkey/registration/"
							+ registrationClient.getRegistrationId() + "/"
							+ params[0].get("deviceId"));
				}

				// Add your data
				List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(
						2);
				nameValuePairs.add(new BasicNameValuePair("clientRequest",
						clientRequest));
				httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));

				// Execute HTTP Post Request
				try {
					HttpClient httpClient;
					if (trust) {
						httpClient = getNewHttpClient();
						trust = false;
					} else {
						httpClient = new DefaultHttpClient();
					}

					if (!isNetworkConnected()) {
						MenuActivity.this.runOnUiThread(new Runnable() {
							public void run() {
								alertbox.setTitle(R.string.connection_error_title);
								alertbox.setMessage(R.string.connection_error_message);
								alertbox.show();

							}
						});
						return null;
					}
					HttpResponse response = httpClient.execute(httpPost);
					HttpEntity entity = response.getEntity();
					String content = EntityUtils.toString(entity);
					return content;
				} catch (SSLPeerUnverifiedException e) {
					MenuActivity.this.runOnUiThread(new Runnable() {
						public void run() {
							showUntrustedCertificate();
						}
					});
					return null;
				}

			} catch (final Exception e) {
				Log.i(this.getClass().getName(),
						"onActivityResult() - IOException while executing the HTTP post request: "
								+ e.getMessage());
				MenuActivity.this.runOnUiThread(new Runnable() {
					public void run() {
						alertbox.setTitle(R.string.error);
						alertbox.setMessage(e.getMessage());
						alertbox.show();
					}
				});
				return null;
			}
		}

		@Override
		protected void onPostExecute(String content) {
			Log.i(this.getClass().getName(),
					"RegisterDeviceSubAsyncTask.onPostExecute()");
			dialog.dismiss();
			try {
				if (content == null) {
					return;
				} else if (!registered
						&& registrationClient
								.verifyRegistrationResponse(content)
						&& registrationClient.isPasscode()) {

					return;
				} else if (!registered
						&& registrationClient
								.verifyRegistrationResponse(content)
						&& !registrationClient.isPasscode()) {
					registerData();
					return;
				} else if (registered
						&& authenticationClient
								.verifyAuthenticationResponse(
										content,
										cursor.getBlob(Constants.RegistrationTableIndexes.SERVER_KEY
												.getCode()))) {
					alertbox.setTitle(R.string.success);
					alertbox.setMessage(MenuActivity.this.getResources()
							.getString(R.string.authentication_finish));
					alertbox.show();
					return;
				} else {
					alertbox.setTitle(R.string.error);
					alertbox.setMessage(MenuActivity.this.getResources()
							.getString(R.string.registration_error));
					alertbox.show();
					return;
				}
			} catch (QuiRKEYAuthenticationException e) {
				alertbox.setTitle(R.string.error);
				alertbox.setMessage(R.string.auth_not_existing);
				alertbox.show();

			} catch (QuiRKEYRegistrationException e) {
				alertbox.setTitle(R.string.error);
				alertbox.setMessage(R.string.reg_duplicated_device);
				alertbox.show();

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	private void registerData() {
		ContentValues registrationData = new ContentValues();
		registrationData.put(RegistrationTable.NAME,
				registrationClient.getUsername());
		registrationData.put(RegistrationTable.SERVER_KEY,
				registrationClient.getServerPublicKey());

		registrationData.put(RegistrationTable.CLIENT_PRIVATE_KEY, clientKey
				.getPrivate().getEncoded());

		registrationData.put(RegistrationTable.CLIENT_PUBLIC_KEY, clientKey
				.getPublic().getEncoded());

		db.delete(RegistrationTable.TABLE, null, null);
		db.insert(RegistrationTable.TABLE, null, registrationData);

		alertbox.setTitle(R.string.success);
		alertbox.setMessage(MenuActivity.this.getResources().getString(
				R.string.registration_finish));
		alertbox.show();

		String[] fields = new String[] { RegistrationTable.NAME,
				RegistrationTable.SERVER_KEY,
				RegistrationTable.CLIENT_PRIVATE_KEY,
				RegistrationTable.CLIENT_PUBLIC_KEY };
		cursor = db.query(RegistrationTable.TABLE, fields, null, null, null,
				null, null);
		if (cursor.moveToFirst()) {
			changeStatus(true);
		}
	}

	public void showUntrustedCertificate() {
		AlertDialog.Builder dialogUntrustedCertificate = new AlertDialog.Builder(
				MenuActivity.this);
		dialogUntrustedCertificate.setCancelable(false);
		dialogUntrustedCertificate.setPositiveButton(R.string.continue_label,
				new DialogInterface.OnClickListener() {
					@SuppressWarnings("unchecked")
					public void onClick(DialogInterface dialog, int which) {
						trust = true;
						new RegisterDeviceSubAsyncTask().execute(params);
					}
				});
		dialogUntrustedCertificate.setNegativeButton(R.string.cancel,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						dialog.cancel();
					}
				});
		dialogUntrustedCertificate
				.setTitle(R.string.untrusted_certificate_title);
		dialogUntrustedCertificate.setMessage(R.string.untrusted_certificate);
		dialogUntrustedCertificate.show();
	}

	public HttpClient getNewHttpClient() {
		try {
			KeyStore trustStore = KeyStore.getInstance(KeyStore
					.getDefaultType());
			trustStore.load(null, null);

			SSLSocketFactory sf = new MySSLSocketFactory(trustStore);
			sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

			HttpParams params = new BasicHttpParams();
			HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
			HttpProtocolParams.setContentCharset(params, HTTP.UTF_8);

			SchemeRegistry registry = new SchemeRegistry();
			registry.register(new Scheme("http", PlainSocketFactory
					.getSocketFactory(), 80));
			registry.register(new Scheme("https", sf, 443));

			ClientConnectionManager ccm = new ThreadSafeClientConnManager(
					params, registry);

			return new DefaultHttpClient(ccm, params);
		} catch (Exception e) {
			return new DefaultHttpClient();
		}
	}

	private boolean isNetworkConnected() {
		ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
		return (cm.getActiveNetworkInfo() != null);
	}

	private void changeStatus(boolean status) {
		TextView textview_registered = (TextView) findViewById(R.id.textview_registered);
		TextView textview_scanInfo = (TextView) findViewById(R.id.textview_info);
		ImageView imageView_registered = (ImageView) findViewById(R.id.image_registered);
		if (status) {
			textview_registered.setText(getResources().getString(
					R.string.device_registered));
			textview_scanInfo.setText(getResources().getString(
					R.string.authenticate_info));
			imageView_registered.setImageResource(R.drawable.green_check);
			registered = true;
			buttonScan.setText(R.string.authenticate);
		} else {
			textview_registered.setText(getResources().getString(
					R.string.device_not_registered));
			textview_scanInfo.setText(getResources().getString(
					R.string.register_info));
			imageView_registered.setImageResource(R.drawable.red_cross);
			registered = false;
			buttonScan.setText(R.string.register);
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		int id = item.getItemId();
		if (id == R.id.button_scan) {
			db.delete(RegistrationTable.TABLE, null, null);
			changeStatus(false);
			Log.i(this.getClass().getName(),
					"buttonDelete.onClick() - device set not registered");
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
