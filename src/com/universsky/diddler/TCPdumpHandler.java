package com.universsky.diddler;

import java.io.IOException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import universsky.diddler.R;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.AdapterView.OnItemClickListener;

public class TCPdumpHandler {

	private static final String capFileName = "diddler_capture.pcap";
	// Constants definition.
	private static final int defaultRefreshRate = 100;
	private static final int defaultBufferSize = 1024;

	// Your Main activity's ids for the View.
	private static final int paramsId = R.id.params_text;
	// private static final int outputId = R.id.output_text;
	// private static final int scrollerId = R.id.scroller;
	private static final int pbarId = R.id.running_progressbar;

	// TextView's refresh rate in ms.

	// Byte[] buffer's size.

	private int refreshRate = 500;
	private int bufferSize = 4096;
	private int countPackets = 0;
	private int MAX_COUNT = 10000;

	private boolean notificationEnabled = false;
	private boolean refreshingActive = false;

	private TCPdump tcpdump = null;

	private Handler isHandler = null;

	private Context mContext = null;
	private SharedPreferences settings = null;
	private NotificationManager nManager = null;
	private Notification notification = null;

	private ProgressBar pbar = null;
	private EditText params = null;
	private List<String> itemList = new ArrayList<String>();
	private List<String> itemList2 = new ArrayList<String>();
	private List<String> headList = new ArrayList<String>();
	private List<String> timeList = new ArrayList<String>();
	private List<String> sizeList = new ArrayList<String>();
	private ListView list = null;
	private Activity activity = null;

	// ///////////////////////////////////////////////////////////////////////////

	private Runnable updateOutputText = new Runnable() {
		public void run() {
			byte[] buffer = new byte[bufferSize];
			try {
				// 打开tcpdump资源文件
				mContext.getResources().openRawResource(R.raw.tcpdump);
				// 获取tcpdump命令执行的结果
				if ((tcpdump.getInputStream().available() > 0) == true) {

					// String getPath = "";
					// String hostName = "";
					// String buffer = "";
					try {
						// 把tcpdump命令执行的结果的 “输出流” 赋值给字节数组buffer
						// int java.io.DataInputStream.read(byte[] buffer, int
						// offset, int length) throws IOException
						tcpdump.getInputStream().read(buffer, 0, bufferSize);
						// 逐行读字节流

						// buffer = tcpdump.getInputStream().readLine();
						// Clears the screen if it's full.
						// if (outputText.length() + buffer.length() >= MaxSize)
						// outputText.setText("");

						// 防止无限加载，导致内存溢出

						if (itemList.size() > MAX_COUNT) {
							// 把itemList置空
							itemList.clear();
							itemList2.clear();
							timeList.clear();
							sizeList.clear();
						}

					} catch (IOException e) {
						stopRefreshing();
						return;
					}
					String bufferStr = new String(buffer);

					// outputText.append(mStr);

					// 匹配出时间，数据包size

					// String regexHead =
					// "\\d{2}\\:\\d{2}\\:\\d{2}\\.\\d{6}\\sIP\\s\\((.*)length\\s\\d+\\)";
					String headRegex = "\\d{2}\\:\\d{2}\\:\\d{2}\\.\\d{6}\\sIP\\s(.*)length(.*)ack\\s\\d.+win\\s\\d.+";
					// String pStr = "GET\\s+[\\x00-\\x7F]*";
					Pattern pHead = Pattern.compile(headRegex);
					Matcher mHead = pHead.matcher(bufferStr);

					String getRegexStr = "GET\\s+[\\x00-\\x7F]*\\nHost:[\\x00-\\x7F]*\\n\\n";
					// String pStr = "GET\\s+[\\x00-\\x7F]*";
					Pattern pGetHttp = Pattern.compile(getRegexStr);
					Matcher mGetHttp = pGetHttp.matcher(bufferStr);

					while (mHead.find() && mGetHttp.find()) {
						String Head = bufferStr.substring(mHead.start(),
								mHead.end());
						headList.add(Head);

						String item = bufferStr.substring(mGetHttp.start(),
								mGetHttp.end());
						itemList.add(item);

					}

					final ArrayList<HashMap<String, Object>> listItem = new ArrayList<HashMap<String, Object>>();
					final ArrayList<HashMap<String, Object>> listItem2 = new ArrayList<HashMap<String, Object>>();
					for (int i = 0, j = 0; i < itemList.size()
							&& j < headList.size(); i++, j++) {
						HashMap<String, Object> map = new HashMap<String, Object>();
						String title = "第" + (countPackets++) + "个HTTP请求: "
								+ headList.get(j);

						map.put("item_title", title);

						// 获取GET path
						String item = itemList.get(i);
						map.put("item_text0", item);
						listItem2.add(map);
						String request = "";
						Matcher m1 = Pattern.compile("GET\\s(.*)\\sHTTP/1.1")
								.matcher(item);
						if (m1.find()) {
							request = item.substring(m1.start(), m1.end());
							map.put("item_text", request);
							listItem.add(map);
						}
					}
					// 生成适配器的Item和动态数组对应的元素

					android.widget.SimpleAdapter listItemAdapter = new android.widget.SimpleAdapter(
							mContext, // Context
							listItem, // List
							R.layout.list_item, // int resource
							new String[] { "item_title", "item_text" }, // String[]
																		// from
							new int[] { R.id.ItemTitle, R.id.ItemText } // int[]
																		// to
					);
					// Sets the data behind this ListView.
					list.setAdapter(listItemAdapter);
					// 选中listview的指定列，选中了，自然就得让这个item可见，自然就滚动咯
					list.setSelection(list.getBottom());
					// 添加点击
					list.setOnItemClickListener(new OnItemClickListener() {
						@Override
						public void onItemClick(AdapterView<?> arg0, View arg1,
								int arg2, long arg3) {
							CharSequence item = (CharSequence) listItem2.get(
									arg2).get("item_text0");
							// Open Declaration Toast
							// android.widget.Toast.makeText(Context context,
							// CharSequence text, int duration)
							// Toast.makeText(mContext, item,
							// Toast.LENGTH_LONG).show();
							Intent intent = new Intent();
							intent.setClass(activity, ItemActivity.class);
							Bundle mBundle = new Bundle();

							mBundle.putCharSequence("item", item);
							intent.putExtras(mBundle);
							mContext.startActivity(intent);
						}

					});

				}
			} catch (IOException e) {
				stopRefreshing();
				return;
			}
			isHandler.postDelayed(updateOutputText, refreshRate);
		}
	};

	@SuppressWarnings("deprecation")
	public TCPdumpHandler(TCPdump tcpdump, Context mContext, Activity activity,
			boolean notificationEnabled) {

		this.activity = activity;
		// Acessing the app's settings.
		settings = mContext.getSharedPreferences(GlobalConstants.prefsName, 0);

		this.tcpdump = tcpdump;
		isHandler = new Handler();

		this.params = (EditText) activity.findViewById(paramsId);
		// this.outputText = (TextView) activity.findViewById(outputId);
		// this.scroller = (View) activity.findViewById(scrollerId);
		this.list = (ListView) activity.findViewById(R.id.listView1);
		this.pbar = (ProgressBar) activity.findViewById(pbarId);

		this.mContext = mContext;
		this.notificationEnabled = notificationEnabled;

		if (notificationEnabled) {
			// Asociating the System's notification service with the
			// notification manager.
			nManager = (NotificationManager) mContext
					.getSystemService(Context.NOTIFICATION_SERVICE);

			// Defining a notification that will be displayed when TCPdump
			// starts.
			notification = new Notification(R.drawable.icon,
					mContext.getString(R.string.tcpdump_notification),
					System.currentTimeMillis());
			notification.setLatestEventInfo(mContext, "diddler", mContext
					.getString(R.string.tcpdump_notification_msg),
					PendingIntent.getActivity(mContext, 0, new Intent(mContext,
							Main.class).setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP
							| Intent.FLAG_ACTIVITY_SINGLE_TOP),
							PendingIntent.FLAG_CANCEL_CURRENT));
			notification.flags |= Notification.FLAG_ONGOING_EVENT;
		}
	}

	public int start(String params) {

		int TCPdumpReturn;

		if ((TCPdumpReturn = tcpdump.start(params)) == 0) {
			// if save to file, the outputText show
			if (settings.getBoolean("saveCheckbox", false) == true) {
			} else {// if not save to file, show on the scroll view
				startRefreshing();
			}

			setProgressbarVisible();
			if (notificationEnabled)
				postNotification();
			return 0;
		} else
			return TCPdumpReturn;
	}

	public int stop() {
		int TCPdumpReturn;
		if ((TCPdumpReturn = tcpdump.stop()) == 0) {
			stopRefreshing();
			setProgressbarInvisible();
			if (notificationEnabled)
				removeNotification();
			return 0;
		} else
			return TCPdumpReturn;
	}

	private void startRefreshing() {
		if (!refreshingActive) {
			isHandler.post(updateOutputText);
			refreshingActive = true;
		}
	}

	private void stopRefreshing() {
		if (refreshingActive) {
			isHandler.removeCallbacks(updateOutputText);
			refreshingActive = false;
		}
	}

	private void postNotification() {
		nManager.notify(0, notification);
	}

	private void removeNotification() {
		nManager.cancel(0);
	}

	private void setProgressbarVisible() {
		pbar.setVisibility(ProgressBar.VISIBLE);
	}

	private void setProgressbarInvisible() {
		pbar.setVisibility(ProgressBar.INVISIBLE);
	}

	public boolean setRefreshRate(int refreshRate) {
		if ((refreshRate > 0) && (tcpdump.getProcessStatus() == false)) {
			this.refreshRate = refreshRate;
			return true;
		} else
			return false;
	}

	public boolean setBufferSize(int bufferSize) {
		if ((bufferSize > 0) && (tcpdump.getProcessStatus() == false)) {
			this.bufferSize = bufferSize;
			return true;
		} else
			return false;
	}

	public boolean checkNetworkStatus() {

		// Variables used for checking the network state.
		final ConnectivityManager connMgr = (ConnectivityManager) mContext
				.getSystemService(Context.CONNECTIVITY_SERVICE);

		final NetworkInfo wifi = connMgr
				.getNetworkInfo(ConnectivityManager.TYPE_WIFI);

		final NetworkInfo mobile = connMgr
				.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);

		if ((wifi.isConnected() == true) || (mobile.isConnected() == true)) {
			return true;
		} else
			return false;
	}

	public void generateCommand() {
		String command1 = "-Av -i any tcp[20:4]=0x47455420";
		params.setText(command1);
	}

}
