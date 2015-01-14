package com.quirkey.mobile;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
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

import android.annotation.SuppressLint;
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
import android.text.InputFilter;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.quirkey.client.ClientAuthenticationTransaction;
import com.hypersocket.quirkey.client.ClientRegistrationTransaction;
import com.hypersocket.quirkey.client.QuiRKEYException;
import com.quirkey.mobile.DBManager.RegistrationTable;

public class MenuActivity extends Activity {

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
	private Dialog dialogSetPasscode;
	private Dialog dialogEnterPasscode;
	private Context context = (Context) this;
	private ImageView icon;

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
		icon = (ImageView) findViewById(R.id.image_registered);

		icon.setOnTouchListener(new OnTouchListener() {
			@SuppressLint("ClickableViewAccessibility")
			@Override
			public boolean onTouch(View v, MotionEvent event) {
				return MenuActivity.this.onTouchEvent(event);
			}
		});
		String[] fields = new String[] { RegistrationTable.NAME,
				RegistrationTable.SERVER_KEY,
				RegistrationTable.CLIENT_PRIVATE_KEY,
				RegistrationTable.CLIENT_PUBLIC_KEY, RegistrationTable.PASSCODE };
		cursor = db.query(RegistrationTable.TABLE, fields, null, null, null,
				null, null);
		if (cursor.moveToFirst()) {
			changeStatus(true);

		}
	}

	private void scanPressed() {
		Intent i = new Intent(MenuActivity.this, CameraActivity.class);
		i.putExtra("registered", registered);
		Log.i(this.getClass().getName(),
				"buttonScan.onClick() - Calling CameraActivity.java");
		MenuActivity.this.startActivityForResult(i,
				Constants.CAMERA_REQUEST_CODE);
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
							InputFilter[] maxLengthFilter = new InputFilter[1];
							maxLengthFilter[0] = new InputFilter.LengthFilter(
									registrationClient.getPasscodeLength()
											.intValue());

							dialogSetPasscode = new Dialog(MenuActivity.this);
							dialogSetPasscode
									.setContentView(R.layout.set_passcode_layout);
							dialogSetPasscode.setTitle(this.getResources()
									.getString(R.string.set_passcode));

							final EditText editTextSetPasscode = (EditText) dialogSetPasscode
									.findViewById(R.id.editText_setPasscode);
							final EditText editTextRepeatPasscode = (EditText) dialogSetPasscode
									.findViewById(R.id.editText_repeatPasscode);

							editTextSetPasscode.setFilters(maxLengthFilter);
							editTextRepeatPasscode.setFilters(maxLengthFilter);

							Button buttonDone = (Button) dialogSetPasscode
									.findViewById(R.id.button_done);

							buttonDone
									.setOnClickListener(new OnClickListener() {

										@Override
										public void onClick(View v) {
											// Done pressed
											Log.i(this.getClass().getName(),
													"buttonDone.onClick()");
											if ("".equals(editTextSetPasscode
													.getText().toString())
													|| "".equals(editTextRepeatPasscode
															.getText()
															.toString())
													|| editTextSetPasscode
															.getText()
															.toString() == null
													|| editTextRepeatPasscode
															.getText()
															.toString() == null) {
												alertbox.setTitle(R.string.error);
												alertbox.setMessage(R.string.passcode_empty_error);
												alertbox.show();
											} else if (editTextSetPasscode
													.getText().toString()
													.length() != registrationClient
													.getPasscodeLength()
													.intValue()
													|| editTextRepeatPasscode
															.getText()
															.toString()
															.length() != registrationClient
															.getPasscodeLength()
															.intValue()) {
												alertbox.setTitle(R.string.error);

												alertbox.setMessage(context
														.getString(
																R.string.passcode_length_error,
																registrationClient
																		.getPasscodeLength()
																		.intValue()));
												alertbox.show();
											} else if (!editTextSetPasscode
													.getText()
													.toString()
													.equals(editTextRepeatPasscode
															.getText()
															.toString())) {
												alertbox.setTitle(R.string.error);
												alertbox.setMessage(R.string.passcode_repeat_error);
												alertbox.show();
											} else {
												InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
												imm.hideSoftInputFromWindow(
														editTextSetPasscode
																.getWindowToken(),
														0);
												dialogSetPasscode.dismiss();
												params.put("passcode",
														editTextSetPasscode
																.getText()
																.toString());
												new RegisterDeviceSubAsyncTask()
														.execute(params);
											}
										}
									});
							dialogSetPasscode.show();
						} else {
							new RegisterDeviceSubAsyncTask().execute(params);
						}

					}
				} catch (QuiRKEYException e) {
					alertbox.setTitle(R.string.transaction_error);
					alertbox.setMessage(e.getMessage());
					alertbox.show();
					return;
					// } catch (QuiRKEYRegistrationException e) {
					// alertbox.setTitle(R.string.transaction_error);
					// alertbox.setMessage(R.string.reg_transaction_error);
					// alertbox.show();
					// return;
					// } catch (QuiRKEYAuthenticationException e) {
					// alertbox.setTitle(R.string.transaction_error);
					// alertbox.setMessage(R.string.auth_transaction_error);
					// alertbox.show();
					// return;

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
						1);
				nameValuePairs.add(new BasicNameValuePair("clientRequest",
						clientRequest));
				httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));

				// Execute HTTP Post Request
				try {
					HttpClient httpClient;
					if (trust) {
						httpClient = getNewHttpClient();
						if (registered) {
							trust = false;
						}
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

		@SuppressWarnings("unchecked")
		@Override
		protected void onPostExecute(String content) {
			Log.i(this.getClass().getName(),
					"RegisterDeviceSubAsyncTask.onPostExecute()");

			try {
				if (content == null) {
					dialog.dismiss();
					return;
				} else if (!registered) {
					String registrationResponse = registrationClient
							.verifyRegistrationResponse(content);
					Map<String, String> registrationResponseParam = new HashMap<String, String>();
					registrationResponseParam.put("registrationResponse",
							registrationResponse);
					new ConfirmRegistrationSubAsyncTask()
							.execute(registrationResponseParam);
					return;
				} else if (registered
						&& authenticationClient
								.verifyAuthenticationResponse(
										content,
										cursor.getBlob(Constants.RegistrationTableIndexes.SERVER_KEY
												.getCode()))) {
					dialog.dismiss();
					alertbox.setTitle(R.string.success);
					alertbox.setMessage(MenuActivity.this.getResources()
							.getString(R.string.authentication_finish));
					alertbox.show();
					return;
				} else {
					dialog.dismiss();
					alertbox.setTitle(R.string.error);
					alertbox.setMessage(MenuActivity.this.getResources()
							.getString(R.string.registration_error));
					alertbox.show();
					trust = false;
					return;
				}
			} catch (QuiRKEYException e) {
				dialog.dismiss();
				alertbox.setTitle(R.string.error);
				alertbox.setMessage(e.getMessage());
				alertbox.show();
				trust = false;

				// } catch (QuiRKEYAuthenticationException e) {
				// alertbox.setTitle(R.string.error);
				// alertbox.setMessage(R.string.auth_not_existing);
				// alertbox.show();
				//
				// } catch (QuiRKEYRegistrationException e) {
				// alertbox.setTitle(R.string.error);
				// alertbox.setMessage(R.string.reg_duplicated_device);
				// alertbox.show();

			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	class ConfirmRegistrationSubAsyncTask extends
			AsyncTask<Map<String, String>, Void, String> {

		protected String doInBackground(Map<String, String>... params) {
			Log.i(this.getClass().getName(),
					"ConfirmRegistrationSubAsyncTask.doInBackground()");

			try {

				String clientRequest;
				HttpPost httpPost;

				clientRequest = params[0].get("registrationResponse");

				httpPost = new HttpPost(registrationClient.getUrl()
						+ "quirkey/confirmRegistration/"
						+ registrationClient.getRegistrationId());

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
					"ConfirmRegisterDeviceSubAsyncTask.onPostExecute()");
			dialog.dismiss();
			// try {
			if ("".equals(content) || content == null
					|| !"success".equals(content)) {
				alertbox.setTitle(R.string.error);
				alertbox.setMessage(MenuActivity.this.getResources().getString(
						R.string.registration_error));
				alertbox.show();
				return;

			} else {
				registerData();
				return;
			}

			// } catch (QuiRKEYAuthenticationException e) {
			// alertbox.setTitle(R.string.error);
			// alertbox.setMessage(R.string.auth_not_existing);
			// alertbox.show();
			//
			// } catch (QuiRKEYRegistrationException e) {
			// alertbox.setTitle(R.string.error);
			// alertbox.setMessage(R.string.reg_duplicated_device);
			// alertbox.show();

			// } catch (IOException e) {
			// e.printStackTrace();
			// }

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
		if (registrationClient.isPasscode()) {
			EditText editTextSetPasscode = (EditText) dialogSetPasscode
					.findViewById(R.id.editText_setPasscode);
			TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
			registrationData.put(
					RegistrationTable.PASSCODE,
					toAES(editTextSetPasscode.getText().toString(),
							telephonyManager.getDeviceId()));
		}

		db.delete(RegistrationTable.TABLE, null, null);
		db.insert(RegistrationTable.TABLE, null, registrationData);

		alertbox.setTitle(R.string.success);
		alertbox.setMessage(MenuActivity.this.getResources().getString(
				R.string.registration_finish));
		alertbox.show();

		String[] fields = new String[] { RegistrationTable.NAME,
				RegistrationTable.SERVER_KEY,
				RegistrationTable.CLIENT_PRIVATE_KEY,
				RegistrationTable.CLIENT_PUBLIC_KEY, RegistrationTable.PASSCODE };
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
		} else {
			textview_registered.setText(getResources().getString(
					R.string.device_not_registered));
			textview_scanInfo.setText(getResources().getString(
					R.string.register_info));
			imageView_registered.setImageResource(R.drawable.red_cross);
			registered = false;
		}
	}

	@SuppressLint("TrulyRandom")
	public static String toAES(final String secret, String keyString) {
		keyString = "0123456789ABCDEF0123456789ABCDEF";
		final SecretKeySpec skeySpec = new SecretKeySpec(new BigInteger(
				keyString, 16).toByteArray(), "AES");
		try {
			final Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			final byte[] encrypted = cipher.doFinal(secret.getBytes());
			return new BigInteger(encrypted).toString(16);
		} catch (final InvalidKeyException e) {
			throw new UnsupportedOperationException(e);
		} catch (final IllegalBlockSizeException e) {
			throw new UnsupportedOperationException(e);
		} catch (final BadPaddingException e) {
			throw new UnsupportedOperationException(e);
		} catch (final NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException(e);
		} catch (final NoSuchPaddingException e) {
			throw new UnsupportedOperationException(e);
		}
	}

	@Override
	public boolean onTouchEvent(MotionEvent event) {
		int action = event.getAction() & MotionEvent.ACTION_MASK;
		switch (action) {
		case MotionEvent.ACTION_UP: {
			Log.i(this.getClass().getName(), "buttonScan.onClick()");
			if (registered
					&& cursor
							.getString(Constants.RegistrationTableIndexes.PASSCODE
									.getCode()) != null) {
				dialogEnterPasscode = new Dialog(MenuActivity.this);
				dialogEnterPasscode
						.setContentView(R.layout.enter_passcode_layout);
				dialogEnterPasscode.setTitle(MenuActivity.this.getResources()
						.getString(R.string.enter_passcode));
				InputFilter[] maxLengthFilter = new InputFilter[1];
				maxLengthFilter[0] = new InputFilter.LengthFilter(8);
				final EditText editTextEnterPasscode = (EditText) dialogEnterPasscode
						.findViewById(R.id.editText_enterPasscode);
				editTextEnterPasscode.setFilters(maxLengthFilter);
				Button buttonDone = (Button) dialogEnterPasscode
						.findViewById(R.id.button_done);

				buttonDone.setOnClickListener(new OnClickListener() {

					@Override
					public void onClick(View v) {
						// Done pressed
						Log.i(this.getClass().getName(), "buttonDone.onClick()");
						TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
						if ("".equals(editTextEnterPasscode.getText()
								.toString())

								|| editTextEnterPasscode.getText().toString() == null
								|| !toAES(
										editTextEnterPasscode.getText()
												.toString(),
										telephonyManager.getDeviceId())
										.equals(cursor
												.getString(Constants.RegistrationTableIndexes.PASSCODE
														.getCode()))) {
							alertbox.setTitle(R.string.error);
							alertbox.setMessage(R.string.passcode_error);
							alertbox.show();
							editTextEnterPasscode.setText("");

						} else {
							InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
							imm.hideSoftInputFromWindow(
									editTextEnterPasscode.getWindowToken(), 0);
							dialogEnterPasscode.dismiss();
							scanPressed();
						}
					}
				});
				dialogEnterPasscode.show();
			} else {
				scanPressed();
			}

			break;
		}
		}
		return true;

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
		if (id == R.id.action_reset) {
			AlertDialog.Builder confirmDialogReset = new AlertDialog.Builder(
					this);
			confirmDialogReset.setTitle(getResources().getString(
					R.string.confirm));
			confirmDialogReset.setMessage(getResources().getString(
					R.string.reset_confirm_title));
			confirmDialogReset.setCancelable(false);
			confirmDialogReset.setPositiveButton(R.string.ok,
					new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							db.delete(RegistrationTable.TABLE, null, null);
							changeStatus(false);
							Log.i(this.getClass().getName(),
									"buttonDelete.onClick() - device set not registered");

						}
					});
			confirmDialogReset.setNegativeButton(R.string.cancel,
					new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							dialog.cancel();
						}
					});
			confirmDialogReset.show();
		}
		return super.onOptionsItemSelected(item);
	}
}
