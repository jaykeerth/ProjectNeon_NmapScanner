package neonpkg;

/* Class for storing previous scan records */

public class ScanRecord {

	String timeStamp;
	String openPorts;
	
	public ScanRecord()
	{
		timeStamp = null;
		openPorts = null;
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
}
