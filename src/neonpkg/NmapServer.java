package neonpkg;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern; 
import java.util.Date;


/* Server - Listens to HTTP requests and sends reply in JSON format */

public class NmapServer extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public NmapServer() {
        super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request,response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String userHost = request.getParameter("userHost");

        PrintWriter out = response.getWriter();
        response.setContentType("text/html");
        response.setHeader("Cache-control", "no-cache, no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "-1");

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader("Access-Control-Max-Age", "86400");

        Gson gson = new Gson(); 
        JsonObject myObj = new JsonObject();
        ScanResult result = requestHandler(userHost);
        JsonElement resultObj = gson.toJsonTree(result);
        
        if(result.getSuccessFlag() == true)
        {
            myObj.addProperty("success", true);
        }
        else 
        {
            myObj.addProperty("success", false);
        }
        
        myObj.add("result", resultObj);
        out.println(myObj.toString());
        out.close();
    }

    /* Handles all requests and responds with scan result consisting of current and previous scans. 
     * Performs validation checks. */
    
    public ScanResult requestHandler(String host) throws IOException
    {
    	ScanResult result = new ScanResult();
    	if(!validateHost(host))
    	    return result;
        
    	ArrayList<String> currentScan = getNmapResult(host);
    	/*current scan will have index 0 set to "None" if Nmap is not able to retrieve 
    	 * scan report for the given host. 
    	 */
    	if(currentScan.get(0).equals("None"))
    		return result;
   
    	ArrayList<ScanRecord> prevScanRecords = getPrevScanRecordsFromDB(currentScan.get(1));
    	
    	ScanUpdate latestUpdate = new ScanUpdate();
    	if(prevScanRecords.size() > 0)
    		 latestUpdate = compareScanRecords(currentScan, prevScanRecords.get(0));
  
    	Date date = new Date();
        Timestamp ts = new Timestamp(date.getTime());
        result = constructScanResult(currentScan, latestUpdate, prevScanRecords, ts);
    
        insertIntoDB(currentScan, prevScanRecords.size(), ts);
    	
        return result;
    }
    
    /* Hostname validation*/ 
    
    private boolean validateHost(String host)
    {
    	String[] tokens = host.split("\\.");
    	boolean isNum = isNumber(tokens);
    	if(isNum) 
    	{
    		if(tokens.length == 4 && isValidIP(tokens))
    			return true;
    		else
    			return false;
    	}
    	else 
    	    return true;
    }
    
    /* Checks if the user input has all numbers */
    
    private boolean isNumber(String[] tokens)
    {
    	for(String token: tokens)
    	{
    		char[] arr = token.toCharArray();
    		for(int i=0; i<arr.length; i++)
    		{
    			if(arr[i] < 48 || arr[i] > 57)
    				return false;
    		}
    	}
    	return true;
    }
    
    /* Checks if the user input is in valid IP address format */
    
    private boolean isValidIP(String[] tokens)
    {
    	int count = 0;
    	for(String token: tokens)
    	{
    		int num = Integer.parseInt(token);
    		if(num < 0 && num > 255)
    			return false;
    		if(num == 0)
    			count++;
    	}
    	if(count == 4)
    			return false;
    	return true;
    }
    
    /* Insert current scan record into Database */
    
    private void insertIntoDB(ArrayList<String> currentScan, int sweepNumber, Timestamp ts)
    {
    	Connection conn = null;  
    	PreparedStatement stmt1 = null;
    	PreparedStatement stmt2 = null;
    	String sql_insertScanTime = null;
    	String sql_insertScanPorts = null;
    	
    	try
    	{
    		Context ctx = (Context) new InitialContext().lookup("java:comp/env");
            conn = ((DataSource) ctx.lookup("jdbc/mysql")).getConnection(); 
            
            sql_insertScanTime = "insert into scan_time "
            		+ "(ip, sweep_number, time_stamp)"
            		+ "values (?, ?, ?)";
            		
            sql_insertScanPorts = "insert into scan_ports "
            		+ "(scan_id, open_port)"
            		+ "values (?, ?)";
            
            conn.setAutoCommit(false);
            
            stmt1 = conn.prepareStatement(sql_insertScanTime, stmt1.RETURN_GENERATED_KEYS);
            stmt1.setString(1, currentScan.get(1).trim());
            stmt1.setInt(2, sweepNumber+1);
            stmt1.setTimestamp(3, ts);
            stmt1.executeUpdate();
            ResultSet rs = stmt1.getGeneratedKeys();
            int scan_id = -1;
            if(rs.next())
            {
            	scan_id = rs.getInt(1);
            }
            
            stmt2 = conn.prepareStatement(sql_insertScanPorts);
            stmt2.setInt(1, scan_id);
            for(int i=2; i<currentScan.size(); i++)
            {
            	stmt2.setInt(2, Integer.parseInt(currentScan.get(i)));
            	stmt2.executeUpdate();
            }
    
            conn.commit();
            
            rs.close();
            stmt1.close();
            stmt2.close();
         
            stmt1 = null;
            stmt2 = null;
            
            conn.close();                                                             
            conn = null;   
            
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
    	finally
    	{
    		if (stmt1 != null) 
            {                                            
                try 
                {                                                         
                    stmt1.close();                                                
                } 
                catch (SQLException sqlEx) 
                {                                
                    sqlEx.printStackTrace();           
                }                                                             
                stmt1 = null;                                            
            }                                                        

            if (stmt2 != null) 
            {                                            
                try 
                {                                                         
                    stmt2.close();                                                
                } 
                catch (SQLException sqlEx) 
                {                                
                    sqlEx.printStackTrace();           
                }                                                             
                stmt2 = null;                                            
            }  
            
            if (conn != null) 
            {                                      
                try 
                {                                                   
                    conn.close();                                          
                } 
                catch (SQLException sqlEx) 
                {                          
                    sqlEx.printStackTrace();    
                }                                                       
                conn = null;                                            
            }                                           
    	}
    }
    
    /* Get previous scan records from Database */
    
    private ArrayList<ScanRecord> getPrevScanRecordsFromDB(String ip) {

        ArrayList<ScanRecord> prevScanRecords = new ArrayList<ScanRecord>();
        ScanRecord record;
        
        Connection conn = null;            
        
        PreparedStatement stmt1 = null;
        PreparedStatement stmt2 = null;
        PreparedStatement stmt3 = null; 
        
        String sql_sweepNumber = null;
        String sql_openPort = null;
        String sql_timeStamp = null;
        
        ResultSet rs1 = null;
        ResultSet rs2 = null;
        ResultSet rs3 = null;

        try 
        {      
            Context ctx = (Context) new InitialContext().lookup("java:comp/env");
            conn = ((DataSource) ctx.lookup("jdbc/mysql")).getConnection(); 

            sql_sweepNumber = "select sweep_number "
            		+ "from scan_time "
            		+ "where ip = ? "
            		+ "order by sweep_number desc";
            
            sql_timeStamp = "select time_stamp "
            		+ "from scan_time "
            		+ "where scan_time.ip = ? "
            		+ "and scan_time.sweep_number = ?";
            
            sql_openPort = "select open_port "
            		+ "from scan_ports, scan_time "
            		+ "where scan_ports.scan_id = scan_time.scan_id "
            		+ "and scan_time.ip = ? "
            		+ "and scan_time.sweep_number = ? ";
            
            stmt1 = conn.prepareStatement(sql_sweepNumber);
            stmt1.setString(1, ip.trim());
            rs1 = stmt1.executeQuery(); 

            ArrayList<Integer> sweepNumbers = new ArrayList<Integer>();
            while(rs1.next())
            { 
            	sweepNumbers.add(Integer.parseInt(rs1.getString("sweep_number")));
            }                                                                         

            if(!sweepNumbers.isEmpty())
            {
            	stmt2 = conn.prepareStatement(sql_timeStamp);
                stmt2.setString(1, ip.trim());
                
                stmt3 = conn.prepareStatement(sql_openPort);
                stmt3.setString(1, ip.trim());
                
                
                for(Integer sweepNumber: sweepNumbers)
                {
                	String timeStamp = "";
                    String openPorts = "";
                    record = new ScanRecord();
                    
                	stmt2.setInt(2, sweepNumber);
                	stmt3.setInt(2, sweepNumber);
                	rs2 = stmt2.executeQuery();
                	
                	while(rs2.next())
                	{
                		timeStamp += rs2.getString("time_stamp");
                		rs3 = stmt3.executeQuery();
                		while(rs3.next())
                		{
                			openPorts = openPorts + rs3.getString("open_port") + ", ";
                		}
                		record.setTimeStamp(timeStamp);
                		record.setOpenPorts(openPorts.substring(0, openPorts.length()-2));
                		prevScanRecords.add(record);
                	}
                }
                rs2.close();
                rs3.close();
                
                stmt2.close();
                stmt3.close();
                
                stmt2 = null;
                stmt3 = null;
            }
            
            rs1.close();
         
            stmt1.close();
            stmt1 = null;

            conn.close();                                                             
            conn = null;                                                   
            
        }                                                               
        catch(Exception e)
        {
        	e.printStackTrace();        
        }                      
        finally 
        {                                                       
            if (stmt1 != null) 
            {                                            
                try 
                {                                                         
                    stmt1.close();                                                
                } 
                catch (SQLException sqlEx) 
                {                                
                    sqlEx.printStackTrace();           
                }                                                             
                stmt1 = null;                                            
            }                                                        

            if (stmt2 != null) 
            {                                            
                try 
                {                                                         
                    stmt2.close();                                                
                } 
                catch (SQLException sqlEx) 
                {                                
                    sqlEx.printStackTrace();           
                }                                                             
                stmt2 = null;                                            
            }  
            
            if (stmt3 != null) 
            {                                            
                try 
                {                                                         
                    stmt3.close();                                                
                } 
                catch (SQLException sqlEx) 
                {                                
                    sqlEx.printStackTrace();           
                }                                                             
                stmt3 = null;                                            
            }  
            
            if (conn != null) 
            {                                      
                try 
                {                                                   
                    conn.close();                                          
                } 
                catch (SQLException sqlEx) 
                {                          
                    sqlEx.printStackTrace();    
                }                                                       
                conn = null;                                            
            }                                                        
        }              
        return prevScanRecords;
    } 
    
    /* Populates ScanResult object with current scan, new updates on ports, previous scan records */
    
    public ScanResult constructScanResult(ArrayList<String> currentScan, ScanUpdate latestUpdate, ArrayList<ScanRecord> prevScanRecords, Timestamp ts)
    {
    	ScanResult result = new ScanResult();
    	
    	result.setHostName(currentScan.get(0));
    	result.setIp(currentScan.get(1));
    	result.setTimeStamp(""+ts);
    	
    	String openPorts = "";
    	for(int i=2; i<currentScan.size(); i++)
    		openPorts = openPorts + ", "+ currentScan.get(i);
  
    	if(openPorts.length() > 0)
    		openPorts = openPorts.substring(1);
    	result.setOpenPorts(openPorts);
    	
    	result.setNewPortsOpened(latestUpdate.getNewPortsOpened() == null? "None": latestUpdate.getNewPortsOpened());
    	result.setNewPortsClosed(latestUpdate.getNewPortsClosed() == null? "None": latestUpdate.getNewPortsClosed());
    	
    	String[] prevScanTimeStamps = new String[prevScanRecords.size()];
    	String[] prevScanOpenPorts = new String[prevScanRecords.size()];
    	
    	int i=0;
    	for(ScanRecord record: prevScanRecords)
    	{
    		prevScanTimeStamps[i] = record.getTimeStamp();
    		prevScanOpenPorts[i] = record.getOpenPorts();
    		i++;
    	}
    	result.setPrevScanTimeStamps(prevScanTimeStamps);
    	result.setPrevScanOpenPorts(prevScanOpenPorts);
    	result.setSuccessFlag(true);
    	return result;
    }
    
    /* Populates ScanUpdate object with new updates on the ports after previous scan */
    
    public ScanUpdate compareScanRecords(ArrayList<String> currentScan, ScanRecord prevScanRecord)
    {
    	ScanUpdate latestUpdate = new ScanUpdate();
    	String[] prevScanOpenPorts = prevScanRecord.openPorts.split(",");
    	String newPortsOpened = "";
    	String newPortsClosed = "";
    	HashSet<Integer> hs = new HashSet<Integer>();

    	for(String port: prevScanOpenPorts)
    		hs.add(Integer.parseInt(port.trim()));
 
    	for(int i=2; i<currentScan.size(); i++)
    	{
    		if(!hs.contains(Integer.parseInt(currentScan.get(i))))
    			newPortsOpened = newPortsOpened + ", "+currentScan.get(i);
    		else
    			hs.remove(Integer.parseInt(currentScan.get(i)));
    	}
 
    	Iterator<Integer> it = hs.iterator();
    	while(it.hasNext())
    		newPortsClosed = newPortsClosed + ", "+it.next();
    	
    	if(newPortsOpened.length() > 0)
    		newPortsOpened = newPortsOpened.substring(1);
    	else
    		newPortsOpened = null;
   
    	if(newPortsClosed.length() > 0)
    		newPortsClosed = newPortsClosed.substring(1);
    	else 
    		newPortsClosed = null;
  
    	latestUpdate.setNewPortsOpened(newPortsOpened);
    	latestUpdate.setNewPortsClosed(newPortsClosed);
  
    	return latestUpdate;
    }
    
    /* Returns parsed result from NMAP command line.
     * In the result ArrayList, index 0 contains host name.
     * Index 1 contains IP address.
     * From index 2, open ports will be added.
     * If NMAP doesn't show proper port information on the command line, 
     * index 0 and 1 will have "None". Remaining indexes will be empty. */
    
    public ArrayList<String> getNmapResult(String host) throws IOException
    {
    	Process process = new ProcessBuilder("/usr/local/bin/nmap", "-p 0-1000", host).start();
        InputStream is = process.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);
        String line;
    
        int count = 0;
        String savedLine = "";
        Pattern p1 = Pattern.compile("PORT");
        Pattern p2 = Pattern.compile("open");
        
        Matcher m1;
        Matcher m2;
        boolean save = false;
        ArrayList<String> output = new ArrayList<String>();
        
        int index = 2;
        output.add(0, "None");
        output.add(1, "None");
        
        while ((line = br.readLine()) != null) 
        {
       	 	if(count++ == 2)
       	 	{
       	 		savedLine += line;
       	 	}
       	 	if(save)
       	 	{
       	 		if(line.equals(""))
       	 			break;
       	 		m2 = p2.matcher(line);
       	 		if(m2.find())
       	 		{
       	 			output.add(index, line.split("/")[0]);
       	 			index++;
       	 		}	 
       	 	}
       	 	m1 = p1.matcher(line);
       	 	if(m1.find())
       	 	{
       	 		save = true;
       	 	}	 
        }
        
        if(output.size() > 2)
        {
        	String[] tokens = savedLine.split(" ");
   		 	String hostName = tokens[tokens.length-2];
   		 	String ip = tokens[tokens.length-1].substring(1, tokens[tokens.length-1].length()-1);
            output.remove(0);
   		 	output.add(0, hostName);
   		 	output.remove(1);
   		 	output.add(1, ip);
        }
        return output;
    }   
}
