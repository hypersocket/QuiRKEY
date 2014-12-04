package com.quirkey.mobile;

import net.sourceforge.zbar.Config;
import net.sourceforge.zbar.Image;
import net.sourceforge.zbar.ImageScanner;
import net.sourceforge.zbar.Symbol;
import net.sourceforge.zbar.SymbolSet;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.hardware.Camera;
import android.hardware.Camera.AutoFocusCallback;
import android.hardware.Camera.PreviewCallback;
import android.hardware.Camera.Size;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.KeyEvent;
import android.widget.FrameLayout;
import android.widget.TextView;

import com.hypersocket.hypersocketauthenticator.R;

/**
 * CameraActivity: Waits for a QR code to scan it
 */

public class CameraActivity extends Activity {
	private Camera mCamera;
	private CameraPreview mPreview;
	private Handler autoFocusHandler;

	ImageScanner scanner;

	private boolean previewing = true;

	static {
		System.loadLibrary("iconv");
	}

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_camera);

		Log.i(this.getClass().getName(), "onCreate()");

		if (this.getIntent().getExtras().getBoolean("registered")) {
			TextView textView_scanInfo = (TextView) findViewById(R.id.textview_scan_info);
			textView_scanInfo.setText(R.string.auth_camera_info);
		}

		setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);

		autoFocusHandler = new Handler();
		mCamera = getCameraInstance();

		/* Instance barcode scanner */
		scanner = new ImageScanner();
		scanner.setConfig(0, Config.X_DENSITY, 3);
		scanner.setConfig(0, Config.Y_DENSITY, 3);

		mPreview = new CameraPreview(this, mCamera, previewCb, autoFocusCB);
		FrameLayout preview = (FrameLayout) findViewById(R.id.cameraPreview);
		preview.addView(mPreview);

	}

	public void onPause() {
		super.onPause();
		Log.i(this.getClass().getName(), "onPause()");
		releaseCamera();
	}

	/** A safe way to get an instance of the Camera object. */
	public static Camera getCameraInstance() {
		Camera c = null;
		try {
			c = Camera.open();
		} catch (Exception e) {
		}
		return c;
	}

	private void releaseCamera() {
		Log.i(this.getClass().getName(), "releaseCamera()");
		if (mCamera != null) {
			previewing = false;
			mCamera.setPreviewCallback(null);
			mCamera.release();
			mCamera = null;
		}
	}

	private Runnable doAutoFocus = new Runnable() {
		public void run() {
			Log.i(this.getClass().getName(), "doAutoFocus.run()");
			if (previewing)
				mCamera.autoFocus(autoFocusCB);
		}
	};

	PreviewCallback previewCb = new PreviewCallback() {
		public void onPreviewFrame(byte[] data, Camera camera) {
			Log.i(this.getClass().getName(), "previewCb.onPreviewFrame()");
			Camera.Parameters parameters = camera.getParameters();
			Size size = parameters.getPreviewSize();

			Image barcode = new Image(size.width, size.height, "Y800");
			barcode.setData(data);

			int result = scanner.scanImage(barcode);

			if (result != 0) {
				previewing = false;
				mCamera.setPreviewCallback(null);
				mCamera.stopPreview();

				SymbolSet syms = scanner.getResults();
				for (Symbol sym : syms) {
					Log.i(this.getClass().getName(),
							"onPreviewFrame() - Scanned data: " + sym.getData());

					Intent resultIntent = new Intent();
					resultIntent.putExtra(Constants.QR_BASE64, sym.getData());
					setResult(Activity.RESULT_OK, resultIntent);

					finish();
					Log.i(this.getClass().getName(),
							"onPreviewFrame() - scan OK");
				}
			}
		}
	};

	// Mimic continuous auto-focusing
	AutoFocusCallback autoFocusCB = new AutoFocusCallback() {
		public void onAutoFocus(boolean success, Camera camera) {
			autoFocusHandler.postDelayed(doAutoFocus, 1000);
		}
	};

	/**
	 * When pressing back the camera is closed and shows the setting screen
	 */
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		Log.i(this.getClass().getName(), "onKeyDown()");
		if ((keyCode == KeyEvent.KEYCODE_BACK)) {
			Log.i(this.getClass().getName(), "onKeyDown() - Back pressed");
			Intent resultIntent = new Intent();
			setResult(Activity.RESULT_CANCELED, resultIntent);

			finish();
			Log.i(this.getClass().getName(), "onPreviewFrame() - scan CANCELED");
		}
		return super.onKeyDown(keyCode, event);
	}
}
