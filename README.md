                                                                        _
                                                                       | \
                ,---------------------------------,                  _/   >
               |      1                            \____         __/     /
               |       \                                \      _/        \
               |        \                3               '-,  |        ,-'
        ______ |         \_             / \                 \_/       /
       / ____/_|  ____  / /   ____  ___/  _\__  ____  ____  / /_  ____|_  ___  _____
      / / __/ _ \/ __ \/ / \ / __ \/ __ \/ __ \/ __ \/ __ \/ / / / /_  / / _ \/ ___/
     / /_/ /  __/ /_/ / /___/ /_/ / /_/ / /_/ / / / / /_/ / / /_/ / / /_/  __/ /
     \____/\___/\____/_____/\____/\__, /\____/_/ /_/\__,_/_/\__, / /___/\___/_/
                \             \  /____/        \           /____/  /
                 |_            \ /              \                 /
                   \            2                \               /
                    ----.                         \             /
                        '-,_                       4            \
                            `-----,                   ,-------,  \
                                   \,~.      ,---^---'         |  \
                                       \    /                   \  |
                                        \  |                     \_|
                                         `-'                    

GeoLogonalyzer is a utility to perform location and metadata lookups on source IP addresses of 
remote access logs. This analysis can identify anomalies based on speed of required travel,
distance, hostname changes, ASN changes, VPN client changes, etc. 

GeoLogonalyzer extracts and processes changes in logon characteristics to reduce analysis requirements. 
For example, if a user logs on 500 times from 1.1.1.1 and then 1 time from 2.2.2.2, GeoLogonalyzer
will create one line of output that shows information related to the change such as:
* Detected anomalies
* Data Center Hosting information identified
* Location information
* ASN information
* Time and distance metrics
----
# Preparation

### MaxMind Databases
1. Make a free account for MaxMind GeoLite at https://www.maxmind.com/en/geolite2/signup
2. Download the 'GeoLite2 City - MaxMind DB binary' from https://www.maxmind.com/en/accounts/current/geoip/downloads
3. Be sure to download <GeoLite2-City_YYYYMMDD.tar.gz> and <GeoLite2-ASN_YYYYMMDD.tar.gz>
4. Extract the MMDB files from the tar.gz files.
5. Place them in the same folder as GeoLogonalyzer.py

###  Python
If you need to use the python source code (such as for modifiying configurations, adding custom
log parsing, or running on *nix/OSX), you will need to install the following dependencies which 
you may not already have:

    netaddr
    python-geoip-python3
    win_inet_pton
    geopy
    geoip2>=2.9.0
    importlib-metadata

A pip requirements.txt is provided for your convenience.

    pip install -r requirements.txt

##### Constants Configuration
The following constants can be modified when running the Python source code to suite your analysis needs:

| Constant Name | Default Value | Description |
|---------------|---------------|-------------|
| RESERVED_IP_COORDINATES | (0, 0) | Default Lat\Long coordinates for IP addresses identified as reserved |
| FAR_DISTANCE | 500 | Threshold in miles for determining if two logons are "far" away from eachother |
| FAST_MPH | 500 | Threshold in miles per hour for determining if two logons are "geoinfeasible" based on distance and time |


### Input
##### CSV (Default)
By default, Geologonalyzer supports **_time sorted_** remote access logs in the following CSV format:

    YYYY-MM-DD HH:MM:SS,user,10.10.10.10,hostname(optional),VPN client (optional)

Example CSV input.csv file (created entirely for demonstration purposes):

    2017-11-23 10:05:02, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-23 11:06:03, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-23 12:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-23 13:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-24 10:07:05, Meghan, 72.229.28.185, Meghan-Tablet, OpenSourceVPNClient
    2017-11-24 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-24 17:15:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-24 17:30:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-24 20:00:00, Meghan, 104.175.79.199, android, AndroidVPNClient
    2017-11-24 21:00:00, Meghan, 104.175.79.199, android, AndroidVPNClient
    2017-11-25 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-25 17:05:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-25 17:10:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-25 17:11:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-25 19:00:00, Harry, 101.0.64.1, andy-pc, OpenSourceVPNClient
    2017-11-26 10:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-26 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-27 10:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-27 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-28 10:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-28 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient
    2017-11-29 10:00:00, Meghan, 72.229.28.185, Meghan-Laptop, CorpVPNClient
    2017-11-29 17:00:00, Harry, 97.105.140.66, Harry-Laptop, CorpVPNClient

##### Custom Log Formats
If you have a log format that is difficult to convert to CSV, GeoLogonalyzer supports
custom log format parsing through modification of the "get_custom_details" function.

For this function, input will be a line of text, and output must contain:

    return time, ip_string, user, hostname, client
    
Here is a Juniper PulseSecure log format and the sample code to extract required fields:

    # Example Juniper Firewall Input line (wrapped on new lines):
    #   Mar 12 10:59:33 FW_JUNIPER <FW_IP> PulseSecure: id=firewall time="2018-03-12 10:59:33" pri=6
    #   fw=<FW_IP> vpn=<VPN_NAME> user=System realm="" roles="" type=mgmt proto= src=<SRC_IP> dst=
    
    # Example function to fill in for "get_custom_details(line):
      # Create regex match object to find data
      juniper_2_ip_user_mo = re.compile("(time=\")([\d\ \-\:]{19})(\" .*)( user\=)(.*?)"
                                        "( realm.*? src=)(.*?)( )")
    
      # Match the regex
      ip_user_match = re.search(juniper_2_ip_user_mo, line)
    
      # Extract timestamp and convert to datetime object from "2017-03-30 00:22:42" format
      time = datetime.strptime(ip_user_match.group(2).strip(), '%Y-%m-%d %H:%M:%S')
    
      # Extract username and source IP (not the <FW_IP>
      user = ip_user_match.group(5).strip()
      ip_string = ip_user_match.group(7).strip()
    
      # Set empty hostname and client since they were not included in input
      hostname = ""
      client = ""
    
      return time, ip_string, user, hostname, client
------
# Execution Syntax
The following command will parse the input.csv shown above and save results to output.csv:

    GeoLogonalyzer --csv input.csv --output output.csv
------
# Output
The output.csv file will include the following column headers:

| Column Header | Description |
|-------------|-----------|
| User | Username of logons compared |
| Anomalies | Flags for anomalies detailed in "Automatic Anomaly Detection" section below |
| 1st Time | Time of 1st compared logon |
| 1st IP | IP Address of 1st compared logon |
| 1st DCH | Datacenter hosting information of 1st compared logon |
| 1st Country | Country associated with IP address of 1st compared logon |
| 1st Region | Region associated with IP address of 1st compared logon |
| 1st Coords | Lat/Long coordinates associated with IP address of 1st compared logon |
| 1st ASN # | ASN number associated with IP address of 1st compared logon |
| 1st ASN Name | ASN name associated with IP address of 1st compared logon |
| 1st VPN Client | VPN client name associated with 1st compared logon |
| 1st Hostname | Hostname associated with 1st compared logon |
| 1st Streak | Count of logons by user from 1st compared source IP address before change |
| 2nd Time | Time of 2nd compared logon |
| 2nd IP | IP Address of 2nd compared logon |
| 2nd DCH | Datacenter hosting information of 2nd compared logon |
| 2nd Country | Country associated with IP address of 2nd compared logon |
| 2nd Region | Region associated with IP address of 2nd compared logon |
| 2nd Coords | Lat/Long coordinates associated with IP address of 2nd compared logon |
| 2nd ASN # | ASN number associated with IP address of 2nd compared logon |
| 2nd ASN Name | ASN name associated with IP address of 2nd compared logon |
| 2nd VPN Client | VPN client name associated with 2nd compared logon |
| 2nd Hostname | Hostname associated with 2nd compared logon |
| Miles Diff | Difference in miles between two associated coordinates of two compared IP addresses |
| Seconds Diff | Difference in time between two compared authentications |
| Miles/Hour | Speed required to physically move from 1st logon location to 2nd logon location by time difference between compared logons. Miles Diff / Seconds Diff |


-------
# Analysis Tips
1. Unless otherwise configured (as described above), RFC1918 and other reserved IP addresses are assigned a geolocation of (0,0) which is located in the Atlantic Ocean near Africa which will skew results.
a. Use the --skip_rfc1918 command line parameter to completely skip any reserved source IP address such as RFC1918. This is useful to reduce false positives if your data includes connections from internal networks such as 10.10.10.10 or 192.168.1.100.

2. Use the Automatic Anomaly Detection flags listed below to quickly identify anomalies. Examples include changes in logons that:
a. require require an infeasible rate of travel (FAST)
b. involve a large change in distance (DISTANCE)
c. involvce a source IP address registered to a datacenter hosting provider such as Digital Ocean or AWS (DCH)
d. changes in ASN (ASN), VPN client name (CLIENT), or source system hostname (HOSTNAME)

3. Look for IP addresses registered to unexpected countries.
4. Analyze the "Streak" count to develop a pattern of logon behavior from a source IP address before a change occurs.
5. Analyze all hostnames to ensure they match standard naming conventions.
6. Analyze all software client names to identify unapproved software.

### Automatic Anomaly Detection
GeoLogonalyzer will try to automatically flag on the following anomalies:

| Flag | Description |
|------|-------------|
| DISTANCE | This flag indicates the distance between the two compared source IP addresses exceeded the configured FAR_DISTANCE constant. This is 500 miles by default. |
| FAST | This flag indicates the speed required to travel between the two compared source IP addresses in the time between the two compared authentications exceeded the configured IMPOSSIBLE_MPH constant. This is 500 MPH by default. Estimate source: https://www.flightdeckfriend.com/how-fast-do-commercial-aeroplanes-fly |
| DCH | This flag indicates that one of the compared IP Addresses is registered to a datacenter hosting provider. |
| ASN | This flag indicates the ASN of the two compared source IP addresses was *_not_* identical. Filtering out source IP address changes *_that do not have this flag*_ may cut down on legitimate logons from nearby locations to review. |
| CLIENT | If VPN client information is processed by GeoLogonalyzer, this flag indicates a change in VPN client name between the two compared authentications. This can help identify use of unapproved VPN client software. |
| HOSTNAME | If hostname information is processed by GeoLogonalyzer, this flag indicates a change in hostname between the two compared authentications. This can help identify use of unapproved systems connecting to your remote access solution. |

------
# Alternate Usage
GeoLogonalyzer can be used to provide metadata lookups on a text file that lists IP addresses one per line. Example ip-input.txt file (created entirely for demonstration purposes):

    1.3.5.7
    10.39.4.5
    127.9.4.5
    34.78.32.14
    192.4.4.3
    asdffasdf
    2.4.5.0
    
Example execution syntax:

    GeoLogonalyzer --ip_only ip-input.txt --output ip-output.csv

Example ip-output.csv:

    ip,location,country,subdivisions,dch_company,asn_number,asn_name
    1.3.5.7,"(23.1167, 113.25)",CN,GD, , , 
    10.39.4.5,"(0, 0)",PRIVATE,PRIVATE,,,
    127.9.4.5,"(0, 0)",RESERVED,RESERVED,,,
    34.78.32.14,"(29.9668, -95.3454)",US,TX, , , 
    192.4.4.3,"(40.6761, -74.573)",US,NJ, ,54735,"TT Government Solutions, Inc."
    asdffasdf,"(0, 0)",INVALID,INVALID,,,
    2.4.5.0,"(43.6109, 3.8772)",FR,"OCC, 34", ,3215,Orange

-----
# Licenses
### GeoLogonalyzer License: 
    https://github.com/mandiant/GeoLogonalyzer/blob/master/LICENSE.txt

### MaxMind Attribution and Credit

    This product includes GeoLite2 data created by MaxMind, available from
    http://www.maxmind.com provided under the Creative Commons Attribution-
    ShareAlike 4.0 International License. Copyright (C) 2012-2018 Maxmind, Inc.
    Copyright (C) 2012-2018 Maxmind, Inc.

### client9 Attribution and Credit

    This product retrieves and operates on data including datacenter
    categorizations retrieved from https://github.com/client9/ipcat/ which
    are Copyright <C> 2018 Client9. This data comes with ABSOLUTELY NO
    WARRANTY; for details go to:
            https://raw.githubusercontent.com/client9/ipcat/master/LICENSE
    The data is free software, and you are welcome to redistribute it under
    certain conditions. See LICENSE for details.

# Limitations
1. All GeoIP lookups are dependent on the accuracy of MaxMind database values
2. All DCH lookups are dependent on the accuracy of open source data
3. VPN or network tunneling services may skew results

# Credits
GeoLogonalyzer was created by David Pany. The project was inspired by research performed by FireEye's data science team including Christopher Schmitt, Seth Summersett, Jeff Johns, Alexander Mulfinger, and more whose work supports live remote access processing in FireEye Helix - https://www.fireeye.com/solutions/helix.html. The "Logonalyzer" name was originally created by @0xF2EDCA5A.

# Contact
Please contact david.pany@mandiant.com or @davidpany on Twitter for bugs, comments, or suggestions. 
