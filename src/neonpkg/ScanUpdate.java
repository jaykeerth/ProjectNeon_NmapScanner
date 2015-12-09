package neonpkg;

/* Class for storing new updates on ports after previous scan */

public class ScanUpdate {

	String newPortsOpened;
	String newPortsClosed;
	
	public ScanUpdate()
	{
		newPortsOpened = null;
		newPortsClosed = null;
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
	public String getNewPortsClosed()
	{
		return newPortsClosed;
	}
	public void setNewPortsClosed(String newPortsClosed)
	{
		this.newPortsClosed = newPortsClosed;
		return;
	}
}
