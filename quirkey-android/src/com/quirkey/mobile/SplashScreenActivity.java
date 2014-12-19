package com.quirkey.mobile;

import java.util.Timer;
import java.util.TimerTask;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import com.quirkey.mobile.R;

/**
 * SplashScreenActivity: Shows an image for a few seconds
 */
public class SplashScreenActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_splash_screen);

		Log.i(this.getClass().getName(), "onCreate()");

		// Executed after the splash screen
		TimerTask task = new TimerTask() {
			@Override
			public void run() {
				Log.i(this.getClass().getName(),
						"onCreate().TimerTask.run() - Splash delay = "
								+ Constants.SPLASH_DELAY);
				Intent mainIntent = new Intent().setClass(
						SplashScreenActivity.this, MenuActivity.class);
				Log.i(this.getClass().getName(),
						"onCreate().TimerTask.run() - Calling MainActivity.java");
				// MenuActivity.java
				startActivity(mainIntent);
				// The activity is finished to avoid showing again
				finish();
			}
		};

		Timer timer = new Timer();
		timer.schedule(task, Constants.SPLASH_DELAY);

	}

	/**
	 * Prevents the user from pressing back button
	 */
	@Override
	public void onBackPressed() {
		// do nothing.
		Log.i(this.getClass().getName(), "onKeyDown() - Back pressed");
	}
}