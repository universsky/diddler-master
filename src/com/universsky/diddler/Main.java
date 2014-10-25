package com.universsky.diddler;

import universsky.diddler.R;

import com.universsky.RootTools.RootTools;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class Main extends Activity {

	public static final String TCPDUMP_PARAMS = "-Av -s 0 -i any tcp[20:4]=0x47455420";
	// Variable declarations for handling the view items in the layout.
	private Button start_button;
	private Button stop_button;
	// private Button read_button;
	private EditText parameters;

	// Variable declarations for handling the TCPdump process.
	private TCPdump tcpdump = null;
	private TCPdumpHandler tcpDumpHandler = null;
	private SharedPreferences settings = null;

	// Variable declarations for handling the options and reader activities.
	private Intent optionsIntent = null;
	private Intent readerIntent = null;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		// Associating the items in the view to the variables.
		start_button = (Button) findViewById(R.id.start_button);
		stop_button = (Button) findViewById(R.id.stop_button);
		// read_button = (Button) findViewById(R.id.read_button);
		parameters = (EditText) findViewById(R.id.params_text);

		// Accessing the app's preferences.
		settings = getSharedPreferences(GlobalConstants.prefsName, 0);

		// Extracting the TCPdump binary to the app folder.
		/**
		 * This method can be used to unpack a binary from the raw resources
		 * folder and store it in /data/data/app.package/files/ This is
		 * typically useful if you provide your own C- or C++-based binary. This
		 * binary can then be executed using sendShell() and its full path.
		 * 
		 * @param context
		 *            the current activity's <code>Context</code>
		 * 
		 * @param sourceId
		 *            resource id; typically <code>R.raw.id</code>
		 * 
		 * @param destName
		 *            destination file name; appended to
		 *            /data/data/app.package/files/
		 * 
		 * @return a <code>boolean</code> which indicates whether or not we were
		 *         able to create the new file.
		 * 
		 *         public static boolean installBinary(Context context, int
		 *         sourceId, String destName) { return installBinary(context,
		 *         sourceId, destName, "700"); }
		 */

		// install tcpdump bin

		/**
		 * This method can be used to unpack a binary from the raw resources
		 * folder and store it in /data/data/app.package/files/
		 */
		if (RootTools.installBinary(Main.this, R.raw.tcpdump, "tcpdump") == false) {

			new AlertDialog.Builder(Main.this)
					.setTitle(R.string.extraction_error)
					.setMessage(R.string.extraction_error_msg)
					.setNeutralButton(R.string.ok, null).show();
		}

		// Creating a new TCPdump object.
		tcpdump = new TCPdump();

		// Creating a TCPdump handler for the TCPdump object created after.
		tcpDumpHandler = new TCPdumpHandler(tcpdump, this, this, true);

		// Obtaining the command from the options that were saved last time
		// Shark was running.
		// tcpDumpHandler.generateCommand();

		String commandParams = TCPDUMP_PARAMS;
		parameters.setText(commandParams);

		start_button.setOnClickListener(new OnClickListener() {
			// Setting the action to perform when the start button is pressed.
			@Override
			public void onClick(View v) {
				startTCPdump();
			}
		});

		stop_button.setOnClickListener(new OnClickListener() {
			// Setting the action to perform when the stop button is pressed.
			@Override
			public void onClick(View v) {
				stopTCPdump();
			}
		});

		BroadcastReceiver connectionReceiver = new BroadcastReceiver() {
			@Override
			public void onReceive(Context context, Intent intent) {
				// Setting the action to be performed when the network status
				// changes.
				if ((tcpDumpHandler.checkNetworkStatus() == false)
						&& (tcpdump.getProcessStatus())) {
					stopTCPdump();
					new AlertDialog.Builder(Main.this)
							.setTitle(
									getString(R.string.network_connection_down))
							.setMessage(
									getString(R.string.network_connection_down_msg))
							.setNeutralButton(getString(R.string.ok), null)
							.show();
				}
			}
		};

		// Registering the BroadcastReceiver and associating it with the
		// connectivity change event.
		registerReceiver(connectionReceiver, new IntentFilter(
				"android.net.conn.CONNECTIVITY_CHANGE"));
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		// Setting the action to perform when returning to this activity from
		// another activity which had been called.
		super.onActivityResult(requestCode, resultCode, data);
		if (resultCode == RESULT_OK && requestCode == 1) {
			if (tcpdump.getProcessStatus()) {
				new AlertDialog.Builder(Main.this)
						.setTitle(getString(R.string.settings_changed))
						.setMessage(getString(R.string.settings_changed_msg))
						.setNeutralButton(getString(R.string.ok), null).show();
			}

			// tcpDumpHandler.generateCommand();
			// String commandParams = TCPDUMP_PARAMS;
			parameters.setText(TCPDUMP_PARAMS);
		}
	}

	@Override
	public void onDestroy() {
		// Setting the action to perform when the Android O.S. kills this
		// activity.
		if (tcpdump.getProcessStatus()) {
			stopTCPdump();
		}
	}

	public boolean onCreateOptionsMenu(Menu menu) {
		// This code makes the activity to show a menu when the device's menu
		// key is pressed.
		menu.add(0, 0, 0, getString(R.string.options_text));
		menu.add(0, 1, 0, getString(R.string.about_text));
		return true;
	}

	public boolean onOptionsItemSelected(MenuItem item) {
		// Setting the action to perform when an option from the menu is
		// selected.
		switch (item.getItemId()) {
		case 0:
			optionsIntent = new Intent(Main.this, Options.class);
			startActivityForResult(optionsIntent, 1);
			return true;
		case 1:
			new AlertDialog.Builder(Main.this).setTitle(R.string.about_text)
					.setMessage(getString(R.string.about_diddler))
					.setNeutralButton(getString(R.string.ok), null).show();
			return true;
		}
		return false;
	}

	/**
	 * Calls TCPdumpHandler to try start the packet capture.
	 */
	private void startTCPdump() {
		if (tcpDumpHandler.checkNetworkStatus()) {
			setTitle("tcpdump " + parameters.getText().toString());
			switch (tcpDumpHandler.start(parameters.getText().toString())) {
			case 0:
				Toast.makeText(Main.this, getString(R.string.tcpdump_started),
						Toast.LENGTH_SHORT).show();
				break;
			case -1:
				Toast.makeText(Main.this,
						getString(R.string.tcpdump_already_started),
						Toast.LENGTH_SHORT).show();
				break;
			case -2:
				new AlertDialog.Builder(Main.this)
						.setTitle(getString(R.string.device_not_rooted_error))
						.setMessage(
								getString(R.string.device_not_rooted_error_msg))
						.setNeutralButton(getString(R.string.ok), null).show();
				break;
			case -4:
				new AlertDialog.Builder(Main.this).setTitle("Error")
						.setMessage(getString(R.string.command_error))
						.setNeutralButton(getString(R.string.ok), null).show();
				break;
			case -5:
				new AlertDialog.Builder(Main.this).setTitle("Error")
						.setMessage(getString(R.string.outputstream_error))
						.setNeutralButton(getString(R.string.ok), null).show();
				break;
			default:
				new AlertDialog.Builder(Main.this).setTitle("Error")
						.setMessage(getString(R.string.unknown_error))
						.setNeutralButton(getString(R.string.ok), null).show();
			}
		} else {
			new AlertDialog.Builder(Main.this)
					.setTitle(getString(R.string.network_connection_error))
					.setMessage(
							getString(R.string.network_connection_error_msg))
					.setPositiveButton(getString(R.string.yes),
							new DialogInterface.OnClickListener() {
								public void onClick(DialogInterface dialog,
										int which) {
									startActivity(new Intent(
											Settings.ACTION_WIRELESS_SETTINGS));
								}
							}).setNegativeButton(getString(R.string.no), null)
					.show();
		}
	}

	/**
	 * Calls TCPdumpHandler to try to stop the packet capture.
	 */
	private void stopTCPdump() {
		setTitle("killall tcpdump");

		switch (tcpDumpHandler.stop()) {
		case 0:
			Toast.makeText(Main.this, getString(R.string.tcpdump_stoped),
					Toast.LENGTH_SHORT).show();
			break;
		case -1:
			Toast.makeText(Main.this,
					getString(R.string.tcpdump_already_stoped),
					Toast.LENGTH_SHORT).show();
			break;
		case -2:
			new AlertDialog.Builder(Main.this)
					.setTitle(getString(R.string.device_not_rooted_error))
					.setMessage(getString(R.string.device_not_rooted_error_msg))
					.setNeutralButton(getString(R.string.ok), null).show();
			break;
		case -4:
			new AlertDialog.Builder(Main.this).setTitle("Error")
					.setMessage(getString(R.string.command_error))
					.setNeutralButton(getString(R.string.ok), null).show();
			break;
		case -5:
			new AlertDialog.Builder(Main.this).setTitle("Error")
					.setMessage(getString(R.string.outputstream_error))
					.setNeutralButton(getString(R.string.ok), null).show();
			break;
		case -6:
			new AlertDialog.Builder(Main.this).setTitle("Error")
					.setMessage(getString(R.string.close_shell_error))
					.setNeutralButton(getString(R.string.ok), null).show();
			break;
		case -7:
			new AlertDialog.Builder(Main.this).setTitle("Error")
					.setMessage(getString(R.string.process_finish_error))
					.setNeutralButton(getString(R.string.ok), null).show();
		default:
			new AlertDialog.Builder(Main.this).setTitle("Error")
					.setMessage(getString(R.string.unknown_error))
					.setNeutralButton(getString(R.string.ok), null).show();
		}

	}

	/**
	 * Tries to launch the reader activity.
	 */
	private void launchReader() {
		readerIntent = new Intent(Main.this, Reader.class);

		if (FileManager.checkFile(GlobalConstants.dirName,
				settings.getString("fileText", "diddler_capture.pcap"))) {
			// if diddler_capture.cap exists
			if (tcpdump.getProcessStatus() == false) {
				startActivity(readerIntent);
			} else {
				new AlertDialog.Builder(Main.this)
						.setTitle(getString(R.string.capture_in_progress_error))
						.setMessage(
								getString(R.string.capture_in_progress_error_msg))
						.setPositiveButton(getString(R.string.yes),
								new DialogInterface.OnClickListener() {
									@Override
									public void onClick(DialogInterface arg0,
											int arg1) {
										stopTCPdump();
										startActivity(readerIntent);
									}
								})
						.setNegativeButton(getString(R.string.no), null).show();
			}
		} else {
			new AlertDialog.Builder(Main.this)
					.setTitle(getString(R.string.file_error))
					.setMessage(getString(R.string.file_error_msg))
					.setNeutralButton(getString(R.string.ok), null).show();
		}
	}
}
