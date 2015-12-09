package neonpkg;

/* Class for storing the final result containing current scan, new updates on ports, previous scan records */

public class ScanResult 
{
	String hostName;
	String ip;
	String timeStamp;
	String openPorts;
	String newPortsOpened;
	String newPortsClosed;
	String[] prevScanTimeStamps;
	String[] prevScanOpenPorts;
	boolean success;
	
	public ScanResult()
	{
		hostName = null;
		ip = null;
		timeStamp = null;
		openPorts = null;
		newPortsOpened = null;
		newPortsClosed = null;
		prevScanTimeStamps = null;
		prevScanOpenPorts = null;
		success = false;
	}
	public String getHostName()
	{
		return hostName;
	}
	public void setHostName(String hostName)
	{
		this.hostName = hostName;
		return;
	}
	public String getIp()
	{
		return ip;
	}
	public void setIp(String ip)
	{
		this.ip = ip;
		return;
	}
	public String getTimeStamp()
	{
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp)
	{
		this.timeStamp = timeStamp;
		return;
	}
	public String getOpenPorts()
	{
		return openPorts;
	}
	public void setOpenPorts(String openPorts)
	{
		this.openPorts = openPorts;
		return;
	}
	public String getNewPortsOpened()
	{
		return newPortsOpened;
	}
	public void setNewPortsOpened(String newPortsOpened)
	{
		this.newPortsOpened = newPortsOpened;
		return;
	}
	public String getNewPortsClosed(String newPortsClosed)
	{
		return newPortsClosed;
	}
	public void setNewPortsClosed(String newPortsClosed)
	{
		this.newPortsClosed = newPortsClosed;
		return;
	}
	public String[] getPrevScanTimeStamps()
	{
		return prevScanTimeStamps;
	}
	public void setPrevScanTimeStamps(String[] prevScanTimeStamps)
	{
		this.prevScanTimeStamps = prevScanTimeStamps;
		return;
	}
	public String[] getPrevScanTimeOpenPorts()
	{
		return prevScanOpenPorts;
	}
	public void setPrevScanOpenPorts(String[] prevScanOpenPorts)
	{
		this.prevScanOpenPorts = prevScanOpenPorts;
		return;
	}
	public boolean getSuccessFlag()
	{
		return success;
	}
	public void setSuccessFlag(boolean success)
	{
		this.success = success;
		return;
	}
}
