package com.universsky.diddler;

/**
 * Allows an Android app to run a TCPdump process as the root user.<br>
 * IMPORTANT: Needs the device to be rooted.
 */
public class TCPdump extends RootShell {

	protected static final String tcpdumpBinaryPath = "/data/data/universsky.diddler/files/tcpdump";

	/**
	 * Parameterless TCPdump class constructor. Calls the superclass
	 * constructor.
	 */
	public TCPdump() {
		super();
	}

	/**
	 * TCPdump class constructor. Opens a root shell and launches TCPdump on it
	 * with the given parameters.
	 * 
	 * @param params
	 *            The parameters that TCPdump will use. For example: -i
	 *            [interface name] -s [snaplen size] -w [filename]
	 * @throws IOException
	 */
	public TCPdump(String params) {
		this();
		start(params);
	}

	/**
	 * TCPdump class destructor. Stops TCPdump if its not already stopped.
	 */
	protected void finalize() {
		if (getProcessStatus() == true)
			stop();
	}

	/**
	 * Launches a TCPdump process on a root shell with the given parameters.
	 * 
	 * @param params
	 *            The parameters that TCPdump will use. For example: -i
	 *            [interface name] -s [snaplen size] -w [filename]
	 * 
	 * @return 0 Everything went OK.<br>
	 *         -1 TCPdump is already running.<br>
	 *         -2 The device isn't rooted.<br>
	 *         -3 Error when running the su command.<br>
	 *         -4 Error when running the TCPdump command.<br>
	 *         -5 Error when flushing the DataOutputStream.
	 * @throws IOException
	 */
	public int start(String params) {
		int r;
		if ((r = openShell()) != 0) {
			return r;
		}
		// àÃ––tcpdumpΩK∂À√¸¡Ó
		// return runCommand(tcpdumpBinaryPath + " " + params + "&");
		return runCommand("tcpdump " + params + "&");
	}

	/**
	 * Stops a TCPdump process which is currently running.
	 * 
	 * @return 0: Everything went OK.<br>
	 *         -1: TCPdump wasn't running.<br>
	 *         -2: The device isn't rooted.<br>
	 *         -4: Error when running the killall command.<br>
	 *         -5: Error when flushing the DataOutputStream.<br>
	 *         -6: Error when closing the shell.<br>
	 *         -7: Error when waiting for the process to finish.
	 */
	public int stop() {
		int r;
		if ((r = runCommand("killall tcpdump")) != 0) {
			return r;
		}
		return closeShell();
	}
}
