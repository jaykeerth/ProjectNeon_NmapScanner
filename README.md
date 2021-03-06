# ProjectNeon_NmapScanner

Author: Jay Keerth

Description:

This is a web application that takes a hostname/ip from the user, scans the ports on the host and returns a list of open ports, previous history of scans on that host, as well as changes after the previous scan. Nmap command line tool is used for scanning the host. MySQL is used for storing the history of scans for a given host. 

Instructions for running the project.

1. Download and install Nmap. Link for Mac --> https://nmap.org/download.html#macosx

2. Make sure Nmap command can be executed on the terminal without sudo. 
For that,
Type "sudo visudo" on a terminal. 
Add "yourusername ALL=NOPASSWD: /usr/local/bin/nmap" at the end of the file.

3. Download and install JavaSE 1.8 jdk and Apache Tomcat v8.

4. Copy ProjectNeon.war file into /Library/Tomcat/webapps/

5. Assuming MySQL is already installed, execute the following commands.
   
   ---> For Database Creation

   create database neon;
   
   use neon;

   ---> For Table Creation:

   create table scan_time(
					   scan_id INT NOT NULL AUTO_INCREMENT,
		               ip VARCHAR(20) NOT NULL,
		               sweep_number INT NOT NULL, 
		               time_stamp TIMESTAMP,
		               PRIMARY KEY (scan_id)
    )ENGINE=INNODB;
                       
	create table scan_ports(
                       record_id INT NOT NULL AUTO_INCREMENT,
                       scan_id INT NOT NULL,
					   open_port INT NOT NULL, 
                       PRIMARY KEY (record_id),
                       FOREIGN KEY (scan_id) 
                           REFERENCES scan_time(scan_id)
                           ON DELETE CASCADE
	)ENGINE=INNODB;

   ---> For Index Creation:

	Alter table scan_time
	add index idx_ipsweep (ip, sweep_number);

	Alter table scan_ports
	add index idx_scanid (scan_id);

6. Update context.xml file with the username/password for mysql.

7. Start the server using the command, 
    sudo /Library/Tomcat/bin/startup.sh

8. Open the browser and enter http://localhost:8080/ProjectNeon/

