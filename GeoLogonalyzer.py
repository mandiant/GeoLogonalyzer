#!/usr/bin/env python
#
#GeoLogonalyzer.py
#Version 1.11
#   Geofeasibility calculator and datacenter cross reference utility
#   customizable for various VPN log formats.
#
#Changes:
#   1.02 - Added check for minimum geoip2 dependency version
#   1.10
#       - Runs in python3 - Thanks to Colby Lahaie!
#       - Clarifies instructions for downloading GeoLite DBs with a free account
#   1.11 - Minor updates
#   1.12 - Updated DCH CSV to more updated source
#
#Description:
#   GeoLogonalyzer will perform location and metadata lookups on source IP
#   addresses and identify anomalies based on speed of required travel,
#   distance, hostname changes, etc.
#
#Usage:
#   python GeoLogonalyzer.py --csv input_file --output output_file.csv
#
#Output:
#   CSV data with the following fields:
#       "User",
#       "Anomalies",
#       "1st Time",
#       "1st IP",
#       "1st DCH",
#       "1st Country",
#       "1st Region",
#       "1st Coords",
#       "1st ASN #",
#       "1st ASN Name",
#       "1st VPN Client",
#       "1st Hostname",
#       "1st Streak",
#       "2nd Time",
#       "2nd IP",
#       "2nd DCH",
#       "2nd Country",
#       "2nd Region",
#       "2nd Coords",
#       "2nd ASN #",
#       "2nd ASN Name",
#       "2nd VPN Client",
#       "2nd Hostname",
#       "Miles Diff",
#       "Seconds Diff",
#       "Miles/Hour"
#
#Analysis Examples:
#
#   Note that the "anomalies" output column attempts to identify suspicious activity detailed below.
#
#   1. Investigate logons that require travel of infeasible miles per hour based on IP geolocation.
#       NOTE: RFC1918 IPs are assigned a lat/long of (0,0) which is in the Atlantic Ocean near Africa
#        and will skew results.
#
#   2. Investigate large location_miles_diff values to find logons from distant locations even if
#       MPH is low.
#       NOTE: RFC1918 IPs are assigned a lat/long of (0,0) which is in the Atlantic Ocean near Africa
#        and will skew results.
#
#   3. Look for logons from IPs registered to unexpected countries.
#
#   4. Analyze source IP ASN names for any unexpected ISP information.
#
#   5. Analyze logons from IPs registered to DCH (DataCenter Hosted) providers.
#
#   6. Analyze "Streak" count to determine how many times the user had logged on from FIRST_IP
#       before switching to SECOND_IP.
#
#   7. Analyze all and detected changes of source hostnames for unexpected naming conventions
#
#   8. Analyze all and detected changes of VPN clients for unauthorized software
#
#Configuration:
#   1. By default, all RFC1918 IP addresses default to the geo coordinates (0, 0) which is in the
#       Atlantic Ocean near Africa.
#       Please edit the RESERVED_IP_COORDINATES constant with your organization's actual coordinates
#       for more accurate results.
#
#   1a. If you wish to totally skip RFC1918 IP addresses, please use the --skip_rfc1918 parameter
#
#   2. Please see example in the get_custom_details function comments to configure custom log
#       parsing.
#
#Limitations:
#   1. All geoip lookups are dependent on accuracy of MaxMind database values
#   2. All CDN lookups are dependent on accuracy of open source data
#   3. VPN or network tunneling services may skew results
#
#Created by David Pany while at Mandiant (FireEye) - 2018
#Email: david.pany@fireeye.com
#Twitter: @davidpany
#
# License:
#
#     https://raw.githubusercontent.com/mandiant/GeoLogonalyzer/master/LICENSE.txt
#
# 3rd party code attribution:
#   This product retrieves and operates on data including datacenter categorizations retrieved from
#   categorizations retrieved from https://github.com/growlfm/ipcat/ which is a version from 
#   https://github.com/client9/ipcat/
#
#   Licenses:
#       https://raw.githubusercontent.com/client9/ipcat/master/LICENSE
#       https://raw.githubusercontent.com/growlfm/ipcat/main/LICENSE
#
#   This product includes GeoLite2 data created by MaxMind, available from http://www.maxmind.com
#   provided under the Creative Commons Attribution-ShareAlike 4.0 International License.
#   Copyright (C) 2012-2018 Maxmind, Inc.
#
#   Mad gr33tz to @0xF2EDCA5A for the "Logonalyzer" name inspiration.
#

from __future__ import print_function
import sys
import re # Might be used for custom line parsing
import argparse
from datetime import datetime
from urllib.request import urlopen
import tarfile
import shutil
import os
import csv
import time
import unicodedata
import importlib.metadata

# Imports that are not likely to be installed by default:
try:
    from netaddr import iprange_to_cidrs, IPAddress
    from netaddr.core import AddrFormatError
except ImportError:
    sys.stderr.write("Please install the netaddr dependency:\n\tpip install netaddr\n")
    sys.exit()

try:
    from geoip import open_database
except ImportError:
    sys.stderr.write("Please install the geoip dependency:\n\tpip install python-geoip-python3\n")
    sys.exit()

try:
    # While not used by GeoLogonalyzer, this import is used by geoip_db.lookup(ip)
    import win_inet_pton
except ImportError:
    sys.stderr.write("Please install the win_inet_pton dependency:\n\tpip install win_inet_pton\n")
    sys.exit()

try:
    from geopy.distance import geodesic
except ImportError:
    sys.stderr.write("Please install the geopy dependency:\n\tpip install geopy\n")
    sys.exit()

try:
    import geoip2.database
    import geoip2.errors
    try: #ensure that geopip2 is 2.9.0 or greater. Older versions cause issues.
        #assert pkg_resources.get_distribution("geoip2").version >= '2.9.0'
        assert importlib.metadata.version("geoip2") >= '2.9.0'
    except AssertionError:
        sys.stderr.write("Please upgrade the geoip dependency:\n\tpip install geoip2>=2.9.0\n")
        sys.exit()
except ImportError:
    sys.stderr.write("Please install the geoip dependency:\n\tpip install geoip2>=2.9.0\n")
    sys.exit()

# Constants
RESERVED_IP_COORDINATES = (0, 0)
FAR_DISTANCE = 500
SECONDS_PER_HOUR = 3600
FAST_MPH = 500
IMPOSSIBLE_MPH = 99999999

def create_geoip_db(pattern=r"GeoLite2-City_\d{8}\.tar\.gz"):
    """Open GeoIP DB if available, download if needed"""
    try:
    # Try to open an existing GeoIP DB
        geoip_db = open_database('GeoLite2-City.mmdb')
        print("GeoLite2 City Found. Success.")
        return geoip_db
    
    # Handling if file not found
    except IOError:
        file_found = False
        file_name = ""
        
        # Look through every file in working directory to identify if the tar.gz exists
        for filename in os.listdir():
            if re.match(pattern, filename):
                # Extract the mmdb from the tar.gz if found
                sys.stderr.write("\nExtracting GeoLite2 City Database.\n")
                with tarfile.open(filename, "r:gz") as tar:
                    tar_directory = tar.getnames()[0]
                    tar.extractall()

                    # Clean up unnecessary files
                    sys.stderr.write("Cleaning up GeoLite2 City Archive.\n")
                    shutil.move("{}/GeoLite2-City.mmdb".format(tar_directory), "GeoLite2-City.mmdb")
                    shutil.rmtree(tar_directory)

                os.remove(filename)

                # Open and return GeoIP DB
                geoip_db = open_database('GeoLite2-City.mmdb')
                print("GeoLite2 City extracted. Success.")
                return geoip_db

        # Provide instructions for manually downloading the GeoIP DB if we fail
        sys.stderr.write("\nCouldn't find the GeoLite2 City DB. Please do the following:\n")
        sys.stderr.write("\t1. Download the 'GeoLite2 City - MaxMind DB binary' from "
                         "https://www.maxmind.com/en/accounts/current/geoip/downloads\n")
        sys.stderr.write("\t\t1a. NOTE: MAXMIND NOW REQUIRES YOU TO CREATE A FREE ACCOUNT TO DOWNLOAD GEOLITE2 GEOLOCATION DATA\n")
        sys.stderr.write("\t2. Make sure the downloaded archive file is named '<GeoLite2-City_YYYYMMDD.tar.gz>' and placed "
            "in the 'GeoLogonalyzer.py' working directory\n")
        sys.stderr.write("\t3. Extract the contents of '<GeoLite2-City_YYYYMMDD.tar.gz>' and make sure the DB file is named "
                         "'GeoLite2-City.mmdb'\n")
        sys.stderr.write("\t4. Place 'GeoLite2-City.mmdb' in the 'GeoLogonalyzer.py' working "
                         "directory\n")
        sys.stderr.write("\t5. Rerun the script\n")
        sys.exit()

def create_asn_db(pattern=r"GeoLite2-ASN_\d{8}\.tar\.gz"):
    """Open ASN DB if available, download if needed"""
    try:
        # Try to open an existing ASN DB
        asn_db_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
        print("GeoLite2 ASN Found. Success.")
        return asn_db_reader

    except IOError:
        file_found = False
        file_name = ""

        for filename in os.listdir():
            if re.match(pattern, filename):
                
                sys.stderr.write("Extracting GeoLite2 ASN Database.\n")
                with tarfile.open(filename, "r:gz") as tar:
                    tar_directory = tar.getnames()[0]
                    tar.extractall()

                    # Clean up unnecessary files
                    sys.stderr.write("Cleaning up GeoLite2 ASN Archive.\n")
                    shutil.move("{}/GeoLite2-ASN.mmdb".format(tar_directory), "GeoLite2-ASN.mmdb")
                    shutil.rmtree(tar_directory)

                os.remove(filename)

                # Open and return ASN DB
                asn_db_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
                print("GeoLite2 ASN extracted. Success.")
                return asn_db_reader

        # Provide instructions for manually downloading the ASN DB if we fail
        sys.stderr.write("\nCouldn't find the GeoLite2 ASN DB. Please do the following:\n")
        sys.stderr.write("\t1. Download the 'GeoLite2 ASN - MaxMind DB binary' from "
                         "https://www.maxmind.com/en/accounts/current/geoip/downloads\n")
        sys.stderr.write("\t\t1a. NOTE: MAXMIND NOW REQUIRES YOU TO CREATE A FREE ACCOUNT TO DOWNLOAD GEOLITE2 GEOLOCATION DATA\n")
        sys.stderr.write("\t2. Make sure the downloaded archive file is named '<GeoLite2-ASN_YYYYMMDD.tar.gz>' and placed "
            "in the 'GeoLogonalyzer.py' working directory\n")
        sys.stderr.write("\t3. Extract the contents of '<GeoLite2-ASN_YYYYMMDD.tar.gz>' and make sure the DB file is named "
                         "'GeoLite2-ASN.mmdb'\n")
        sys.stderr.write("\t4. Place 'GeoLite2-ASN.mmdb' in the 'GeoLogonalyzer.py' working "
                         "directory\n")
        sys.stderr.write("\t5. Rerun the script\n")
        sys.exit()

def create_dch_dict():
    """Download datacenter CSV and create dictionary of cidr ranges"""

    sys.stderr.write("\nDownloading DCH (data center hosting) data from "
                     "https://raw.githubusercontent.com/growlfm/ipcat/main/datacenters.csv\n")
    dch_response = urlopen('https://raw.githubusercontent.com/growlfm/ipcat/main/datacenters.csv')

    dch_file = dch_response.read()
    dch_dict = {}
    dch_list = dch_file.decode('utf-8').split("\n")

    # Read downloaded DCH CSV and parse into dch_list
    sys.stderr.write("Creating DCH Database.\n")
    for line in dch_list:
        if line:
            line_list = line.split(",")
            first_ip = line_list[0].strip()
            last_ip = line_list[1].strip()
            dch_company = line_list[2]
            for cidr_range in iprange_to_cidrs(first_ip, last_ip):
                dch_dict[cidr_range] = dch_company

    sys.stderr.write("Completed DCH Database. Parsing log now.\n\n")
    return dch_dict

# Sections that convert lines to time, user, ip_string, hostname, client
def get_csv_details(line):
    """Convert predefined csv format to time, user, ip_string, hostname, client"""
    line_list = line.split(",")
    time = datetime.strptime(line_list[0].strip(), '%Y-%m-%d %H:%M:%S') # ex. 2017-05-15 13:56:23
    user = line_list[1].strip()
    ip_string = line_list[2].strip()

    # Try to parse hostname and client which are optional
    try:
        hostname = line_list[3].strip()
    except IndexError:
        hostname = " "
    try:
        client = line_list[4].strip()
    except IndexError:
        client = " "
    return time, ip_string, user, hostname, client

def get_custom_details(line):
    """Reserved for custom line parsing. Be sure to remove sys.exit() when using."""
    # This function should be used to parse custom line formats and return:
    #   time, ip_string, user, hostname, client
    #
    # Example Juniper Firewall Input line (wrapped on new lines):
    #   Mar 12 10:59:33 FW_JUNIPER <FW_IP> PulseSecure: id=firewall time="2018-03-12 10:59:33" pri=6
    #   fw=<FW_IP> vpn=<VPN_NAME> user=System realm="" roles="" type=mgmt proto= src=<SRC_IP> dst=
    #
    # Example function to fill in for "get_custom_details(line):
    #   # Create regex match object to find data
    #   juniper_2_ip_user_mo = re.compile("(time=\")([\d\ \-\:]{19})(\" .*)( user\=)(.*?)"
    #                                     "( realm.*? src=)(.*?)( )")
    #
    #   # Match the regex
    #   ip_user_match = re.search(juniper_2_ip_user_mo, line)
    #
    #   # Extract timestamp and convert to datetime object from "2017-03-30 00:22:42" format
    #   time = datetime.strptime(ip_user_match.group(2).strip(), '%Y-%m-%d %H:%M:%S')
    #
    #   # Extract username and source IP (not the <FW_IP>
    #   user = ip_user_match.group(5).strip()
    #   ip_string = ip_user_match.group(7).strip()
    #
    #   # Set empty hostname and client since they were not included in input
    #   hostname = ""
    #   client = ""
    #
    #   return time, ip_string, user, hostname, client

    sys.stderr.write("### It doesn't appear that the custom argument is configured. Quitting.\n\n")
    sys.exit()

def calculate_logon_differences(user_list):
    """Calculate differences when a user has a source IP change"""

    difference_dict = {}

    # Calculate location difference, miles per second, and any DCH info
    difference_dict["user"] = user_list[0]["user"]

    # Create empty anomalies set to track suspicious flags
    difference_dict["anomalies"] = set()

    # "location" is coordinates and vincentrify calculates miles between coordinates
    difference_dict["first_location"] = user_list[0]["location"]
    difference_dict["second_location"] = user_list[1]["location"]
    difference_dict["location_miles_diff"] = geodesic(difference_dict["first_location"],
                                                      difference_dict["second_location"]).miles

    # Add anomaly if distance is far
    if difference_dict["location_miles_diff"] >= FAR_DISTANCE:
        difference_dict["anomalies"].add("DISTANCE")

    # Calculate time between logons of changed source IP
    difference_dict["first_time"] = user_list[0]["time"]
    difference_dict["second_time"] = user_list[1]["time"]
    difference_dict["time_seconds_diff"] = abs((difference_dict["second_time"] -
                                                difference_dict["first_time"]).total_seconds())

    # Calculate miles per hour required to logon physically from source IP addresses
    try:
        difference_dict["miles_per_hour"] = ((difference_dict["location_miles_diff"] /
                                              difference_dict["time_seconds_diff"]) *
                                             SECONDS_PER_HOUR)
    except ZeroDivisionError:
        if difference_dict["location_miles_diff"] == 0:
            difference_dict["miles_per_hour"] = 0
        else:
            difference_dict["miles_per_hour"] = IMPOSSIBLE_MPH

    # Add an anomaly if travel is fast
    if difference_dict["miles_per_hour"] >= FAST_MPH:
        difference_dict["anomalies"].add("FAST")

    # Find country registered to IP address
    difference_dict["first_country"] = user_list[0]["country"]
    difference_dict["second_country"] = user_list[1]["country"]

    # Find subdivision such as state, territory, city, etc. registered to source IP
    difference_dict["first_subdivision"] = user_list[0]["subdivisions"]
    difference_dict["second_subdivision"] = user_list[1]["subdivisions"]

    # Find source IP addresses
    difference_dict["first_ip"] = user_list[0]["ip"]
    difference_dict["second_ip"] = user_list[1]["ip"]

    # Find datacenter hosting company if any for IP addresses
    difference_dict["first_ip_dch_company"] = user_list[0]["dch_company"]
    difference_dict["second_ip_dch_company"] = user_list[1]["dch_company"]

    # Add anomaly if DCH detected
    if (difference_dict["first_ip_dch_company"] != " " or
            difference_dict["second_ip_dch_company"] != " "):
        difference_dict["anomalies"].add("DCH")

    # Find ASN Numbers
    difference_dict["first_asn_number"] = user_list[0]["asn_number"]
    difference_dict["second_asn_number"] = user_list[1]["asn_number"]

    # Find ASN Names
    difference_dict["first_asn_name"] = user_list[0]["asn_name"]
    difference_dict["second_asn_name"] = user_list[1]["asn_name"]

    # Add anomaly if ASN change detected
    if difference_dict["first_asn_name"] != difference_dict["second_asn_name"]:
        difference_dict["anomalies"].add("ASN")

    # Find VPN Client Names
    difference_dict["first_client"] = user_list[0]["client"]
    difference_dict["second_client"] = user_list[1]["client"]

    # Add anomaly if VPN Client change detected
    if difference_dict["first_client"] != difference_dict["second_client"]:
        difference_dict["anomalies"].add("CLIENT")

    # Find System Hostnames
    difference_dict["first_hostname"] = user_list[0]["hostname"]
    difference_dict["second_hostname"] = user_list[1]["hostname"]

    # Add anomaly if source hostname change detected
    if difference_dict["first_hostname"] != difference_dict["second_hostname"]:
        difference_dict["anomalies"].add("HOSTNAME")

    # Find streak of previous logon information
    difference_dict["first_streak"] = user_list[0]["ip_streak"]

    # Combine anomalies into string for output
    difference_dict["anomalies_string"] = "|".join(difference_dict["anomalies"])

    return difference_dict

def diff_dict_to_list(logon_diff_dict):
    """Convert logon_diff_dict to list for printing"""
    return ([str(logon_diff_dict.get("user", "")),
             str(logon_diff_dict.get("anomalies_string", "")),
             str(logon_diff_dict.get("first_time", "")),
             str(logon_diff_dict.get("first_ip", "")),
             str(logon_diff_dict.get("first_ip_dch_company", "")),
             str(logon_diff_dict.get("first_country", "")),
             str(logon_diff_dict.get("first_subdivision", "")),
             str(logon_diff_dict.get("first_location", "")),
             str(logon_diff_dict.get("first_asn_number", "")),
             str(logon_diff_dict.get("first_asn_name", "")),
             str(logon_diff_dict.get("first_client", "")),
             str(logon_diff_dict.get("first_hostname", "")),
             str(logon_diff_dict.get("first_streak", "")),
             str(logon_diff_dict.get("second_time", "")),
             str(logon_diff_dict.get("second_ip", "")),
             str(logon_diff_dict.get("second_ip_dch_company", "")),
             str(logon_diff_dict.get("second_country", "")),
             str(logon_diff_dict.get("second_subdivision", "")),
             str(logon_diff_dict.get("second_location", "")),
             str(logon_diff_dict.get("second_asn_number", "")),
             str(logon_diff_dict.get("second_asn_name", "")),
             str(logon_diff_dict.get("second_client", "")),
             str(logon_diff_dict.get("second_hostname", "")),
             str(logon_diff_dict.get("location_miles_diff", "")),
             str(logon_diff_dict.get("time_seconds_diff", "")),
             str(logon_diff_dict.get("miles_per_hour", ""))])

def  reserved_ip_check(ip_string):
    """determine if IP address in RFC1918 or reserved"""

    # IP details for invalid IP addresses
    invalid_ip_details = {"country":"INVALID",
                          "location":RESERVED_IP_COORDINATES,
                          "subdivisions":"INVALID",
                          "dch_company":"",
                          "asn_number":"",
                          "asn_name":""}

    # IP details for MULTICAST IP addresses
    multicast_ip_details = {"country":"MULTICAST",
                            "location":RESERVED_IP_COORDINATES,
                            "subdivisions":"MULTICAST",
                            "dch_company":"",
                            "asn_number":"",
                            "asn_name":""}

    # IP details for PRIVATE IP addresses
    private_ip_details = {"country":"PRIVATE",
                          "location":RESERVED_IP_COORDINATES,
                          "subdivisions":"PRIVATE",
                          "dch_company":"",
                          "asn_number":"",
                          "asn_name":""}

    # IP details for RESERVED IP addresses
    reserved_ip_details = {"country":"RESERVED",
                           "location":RESERVED_IP_COORDINATES,
                           "subdivisions":"RESERVED",
                           "dch_company":"",
                           "asn_number":"",
                           "asn_name":""}

    # IP details for NETMASK IP addresses
    netmask_ip_details = {"country":"NETMASK",
                          "location":RESERVED_IP_COORDINATES,
                          "subdivisions":"NETMASK",
                          "dch_company":"",
                          "asn_number":"",
                          "asn_name":""}

    # IP details for HOSTMASK IP addresses
    hostmask_ip_details = {"country":"HOSTMASK",
                           "location":RESERVED_IP_COORDINATES,
                           "subdivisions":"HOSTMASK",
                           "dch_company":"",
                           "asn_number":"",
                           "asn_name":""}

    # IP details for LOOPBACK IP addresses
    loopback_ip_details = {"country":"LOOPBACK",
                           "location":RESERVED_IP_COORDINATES,
                           "subdivisions":"LOOPBACK",
                           "dch_company":"",
                           "asn_number":"",
                           "asn_name":""}

    # Check to see if IP matches a reserved category
    try:
        ip_address = IPAddress(ip_string)
    except AddrFormatError:
        return invalid_ip_details

    if ip_address.is_multicast():
        return multicast_ip_details

    elif ip_address.is_ipv4_private_use():
        return private_ip_details

    elif ip_address.is_reserved():
        return reserved_ip_details

    elif ip_address.is_netmask():
        return netmask_ip_details

    elif ip_address.is_hostmask():
        return hostmask_ip_details

    elif ip_address.is_loopback():
        return loopback_ip_details

    elif ip_address.is_unicast() and not ip_address.is_ipv4_private_use():
        # Boolean to be returned if IP is Public
        ip_reserved = False
        return ip_reserved

    else:
        return invalid_ip_details

def find_dch(ip_string, dch_dict):
    """Find if the IP exists in a DCH subnet from our created database"""

    for cidr_range, company in dch_dict.items():
        if IPAddress(ip_string) in cidr_range:
            return company

    # If we didn't find a DCH Match, return ""
    return ""

def main(args):
    """Main Function"""

    # Create a cache of IP address metadata to avoid looking up location and DCH data for known IPs
    ip_cache = {}

    # Create user_dict to keep track of user sessions
    user_dict = {}

    # Create MaxMind ASN DB
    asn_db_reader = create_asn_db()

    # Create MaxMind city DB
    geoip_db = create_geoip_db()

    # Create DCH dict
    dch_dict = create_dch_dict()

    # Ddetermine which type of log we have based on argument
    if args.csv:
        input_path = args.csv
    elif args.ip_only:
        input_path = args.ip_only
    elif args.custom:
        input_path = args.custom

    # Print an error message if the argument is not recognized and exit
    else:
        sys.stderr.write("\n\nDidn't recognize your input argument! Please try again.\n")
        sys.exit()

    # Determine if user wants to skip RFC1918 source IP addresses
    if args.skip_rfc1918:
        skip_rfc1918 = True
    else:
        skip_rfc1918 = False

    # Create output file
    output_file = open("{}".format(args.output), "w", newline='')
    csv_writer = csv.writer(output_file, delimiter=',', quotechar='"',
                            quoting=csv.QUOTE_MINIMAL)

    # Print appropriate headers to output file
    if args.ip_only:
        csv_writer.writerow(["ip", "location", "country", "subdivisions", "dch_company",
                             "asn_number", "asn_name"])
    else:
        diff_dict = {"user":"User",
                     "anomalies_string":"Anomalies",
                     "first_time":"1st Time",
                     "first_ip":"1st IP",
                     "first_ip_dch_company":"1st DCH",
                     "first_country":"1st Country",
                     "first_subdivision":"1st Region",
                     "first_location":"1st Coords",
                     "first_asn_number":"1st ASN #",
                     "first_asn_name":"1st ASN Name",
                     "first_client":"1st VPN Client",
                     "first_hostname":"1st Hostname",
                     "first_streak":"1st Streak",
                     "second_time":"2nd Time",
                     "second_ip":"2nd IP",
                     "second_ip_dch_company":"2nd DCH",
                     "second_country":"2nd Country",
                     "second_subdivision":"2nd Region",
                     "second_location":"2nd Coords",
                     "second_asn_number":"2nd ASN #",
                     "second_asn_name":"2nd ASN Name",
                     "second_client":"2nd VPN Client",
                     "second_hostname":"2nd Hostname",
                     "location_miles_diff":"Miles Diff",
                     "time_seconds_diff":"Seconds Diff",
                     "miles_per_hour":"Miles/Hour"}

        csv_writer.writerow(diff_dict_to_list(diff_dict))

    # Open input file and pull time, ip, user, hostname, client out of each line as specified by
    # argument
    with open(input_path, "r") as input_file:

        # Look at every line
        for line in input_file:

            try:
                if args.csv:
                    # Parse predetermined CSV format
                    time, ip_string, user, hostname, client = get_csv_details(line)

                elif args.ip_only:
                    # Parse a file of only IP addresses
                    ip_string = line.strip()
                    time = " "
                    user = " "

                elif args.custom:
                    # Reserved for custom use
                    time, ip_string, user, hostname, client = get_custom_details(line)

                else:
                    sys.stderr.write("Unsupported log type! Try 'GeoLogonalyzer.py -h'\n\n"
                                     "Quitting!\n")
                    sys.exit()

            # If a line has errors, print the error and keep going
            except AttributeError as errormessage:
                sys.stderr.write("### Attribute Error with line: {}\n".format(line))
                sys.stderr.write("{}\t\n".format(errormessage))
                continue
            except ValueError as errormessage:
                sys.stderr.write("### ValueError with line: {}\n".format(line))
                sys.stderr.write("{}\t\n".format(errormessage))
                continue

            # Skip lines without usernames or IPs since there is no value to add
            if not user:
                continue
            if not ip_string:
                continue

            # Check if ip is reserved or doesn't exist
            reserved_ip_details = reserved_ip_check(ip_string)
            if reserved_ip_check(ip_string):
                country = reserved_ip_details["country"]
                location = reserved_ip_details["location"]
                subdivisions = reserved_ip_details["subdivisions"]
                dch_company = reserved_ip_details["dch_company"]
                asn_number = reserved_ip_details["asn_number"]
                asn_name = reserved_ip_details["asn_name"]

                # Skip RFC1918 source IP Addresses if desired
                if skip_rfc1918:
                    continue

            else:
                #if we have a non-reserved IP, look up location and DCH

                if ip_string in ip_cache:
                    # see if we have seen this IP before and looked it up in the DB
                    country = ip_cache[ip_string]["country"]
                    location = ip_cache[ip_string]["location"]
                    subdivisions = ip_cache[ip_string]["subdivisions"]
                    dch_company = ip_cache[ip_string]["dch_company"]
                    asn_number = ip_cache[ip_string]["asn_number"]
                    asn_name = ip_cache[ip_string]["asn_name"]

                else:
                    # If we haven't looked up this IP before, let's get the info and cache it

                    # MaxMind geoip DB lookup
                    geoip_db_match = geoip_db.lookup(ip_string)

                    # Find Country from MaxMind geoip DB
                    try:
                        country = geoip_db_match.country
                    except AttributeError:
                        country = "None"
                    ip_cache[ip_string] = {"country":country}

                    # Find Coordinates from MaxMind geoip DB
                    try:
                        location = geoip_db_match.location
                    except AttributeError:
                        location = (0, 0)
                    ip_cache[ip_string]["location"] = location

                    # Find Subdivisions from MaxMind geoip DB
                    try:
                        subdivisions = ", ".join(geoip_db_match.subdivisions)
                    except AttributeError:
                        subdivisions = "None"
                    ip_cache[ip_string]["subdivisions"] = subdivisions

                    # Find DataCenter Hosting Information from open source data
                    try:
                        dch_company = find_dch(ip_string, dch_dict)
                        if dch_company == "":
                            dch_company = " "
                    except AttributeError:
                        dch_company = " "
                    ip_cache[ip_string]["dch_company"] = dch_company

                    # MaxMind asn DB lookup
                    try:
                        asn_db_match = asn_db_reader.asn(ip_string)
                    except geoip2.errors.AddressNotFoundError:
                        sys.stderr.write("\n   {} not found in ASN database.\n".format(ip_string))
                        asn_db_match = None

                    # Find ASN number from MaxMind ASN DB
                    try:
                        asn_number = asn_db_match.autonomous_system_number
                    except AttributeError:
                        asn_number = " "
                    ip_cache[ip_string]["asn_number"] = asn_number

                    # Find ASN organization name from MaxMind ASN DB
                    try:
                        asn_name = asn_db_match.autonomous_system_organization
                    except AttributeError:
                        asn_name = " "
                    ip_cache[ip_string]["asn_name"] = asn_name

            # If the input is IPs only
            if args.ip_only:
                csv_writer.writerow([str(ip_string), str(location), str(country), str(subdivisions),
                                     str(dch_company), str(asn_number), str(asn_name)])

            # If the input is an actual log, start doing user matching or tracking
            else:

                # If there was a previous logon of this user account detected
                if user in user_dict:

                    # Just confirm that there is only 1 previous logon, no reason this should fail
                    if len(user_dict[user]) == 1:

                        # Add the second logon to the tracker
                        user_dict[user].append({"user":user,
                                                "time":time,
                                                "ip":ip_string,
                                                "dch_company":dch_company,
                                                "country":country,
                                                "location":location,
                                                "subdivisions":subdivisions,
                                                "ip_streak":1,
                                                "asn_number":asn_number,
                                                "asn_name":asn_name,
                                                "hostname":hostname,
                                                "client":client})

                        # If the second logon has a different source IP, source hostname, or
                        # VPN client than the previously seen logon, calculate the differences
                        if user_dict[user][0]["ip"] != user_dict[user][1]["ip"]:
                            logon_diff_dict = calculate_logon_differences(user_dict[user])
                            logon_diff_list = diff_dict_to_list(logon_diff_dict)
                            csv_writer.writerow(logon_diff_list)

                        elif user_dict[user][0]["hostname"] != user_dict[user][1]["hostname"]:
                            logon_diff_dict = calculate_logon_differences(user_dict[user])
                            logon_diff_list = diff_dict_to_list(logon_diff_dict)
                            csv_writer.writerow(logon_diff_list)

                        elif user_dict[user][0]["client"] != user_dict[user][1]["client"]:
                            logon_diff_dict = calculate_logon_differences(user_dict[user])
                            logon_diff_list = diff_dict_to_list(logon_diff_dict)
                            csv_writer.writerow(logon_diff_list)

                        # If it's the same source IP, just increment the counter for the newest
                        # logon
                        else:
                            user_dict[user][1]["ip_streak"] = user_dict[user][0]["ip_streak"] + 1

                        # Since we only care about diffs, drop the older logon and wait to see if
                        # the next one is different
                        user_dict[user].pop(0)

                    # If for some reason there is not exactly 1 previous logon recorded, raise an
                    # error
                    else:
                        assert "error" == "too many records in list"

                else:
                    # If we have never seen this user before
                    user_dict[user] = [{"user":user,
                                        "time":time,
                                        "ip":ip_string,
                                        "dch_company":dch_company,
                                        "country":country,
                                        "location":location,
                                        "subdivisions":subdivisions,
                                        "ip_streak":1,
                                        "asn_number":asn_number,
                                        "asn_name":asn_name,
                                        "hostname":hostname,
                                        "client":client}]

    # Print information for the last logon streak of each user
    # Useful if there are no source IP changes for that user
    for user, logon_info in user_dict.items():

        if len(logon_info) != 1:
            # Catch if a user has more than 1 logon remaining, which should not happen
            assert "more than one (1)" == " logon session remaining"

        else:
            # Prepare data of last streak for printing
            first_time = logon_info[0]["time"]
            first_ip = logon_info[0]["ip"]
            first_ip_dch_company = logon_info[0]["dch_company"]
            first_country = logon_info[0]["country"]
            first_subdivision = logon_info[0]["subdivisions"]
            first_location = logon_info[0]["location"]
            first_streak = logon_info[0]["ip_streak"]
            first_asn_number = logon_info[0]["asn_number"]
            first_asn_name = logon_info[0]["asn_name"]
            first_client = logon_info[0]["client"]
            first_hostname = logon_info[0]["hostname"]

            # The only possible anomaly for unchanged or last logon records could be DCH,
            # so add that in here if applicable
            if first_ip_dch_company not in [" ", ""]:
                first_anomalies = "DCH"
            else:
                first_anomalies = " "

        # Prepare last streak data for output
        last_streak_dict = {"user":user,
                            "anomalies_string":".".join(first_anomalies),
                            "first_time":first_time,
                            "first_ip":first_ip,
                            "first_ip_dch_company":first_ip_dch_company,
                            "first_country":first_country,
                            "first_subdivision":first_subdivision,
                            "first_location":first_location,
                            "first_asn_number":first_asn_number,
                            "first_asn_name":first_asn_name,
                            "first_client":first_client,
                            "first_hostname":first_hostname,
                            "first_streak":first_streak}

        # Convert data to list and write to output
        last_streak_list = diff_dict_to_list(last_streak_dict)
        csv_writer.writerow(last_streak_list)

    # Always be polite!
    sys.stderr.write("\n\nComplete! Thanks for using GeoLogonalyzer.py.")
    output_file.close()

if __name__ == "__main__":

    # Welcome art

    art = ("\n\n\n                                                                      _\n"
           "                                                                     | \\\n"
           "              ,---------------------------------,                  _/   >\n"
           "             |      1                            \\____         __/     /\n"
           "             |       \\                                \\      _/        \\\n"
           "             |        \\                3               '-,  |        ,-'\n"
           "      ______ |         \\_             / \\                 \\_/       /\n"
           "     / ____/_|  ____  / /   ____  ___/  _\\__  ____  ____  / /_  ____|_  ___  _____\n"
           "    / / __/ _ \\/ __ \\/ / \\ / __ \\/ __ \\/ __ \\/ __ \\/ __ \\/ / / / /_  / / _ \\/ ___/\n"
           "   / /_/ /  __/ /_/ / /___/ /_/ / /_/ / /_/ / / / / /_/ / / /_/ / / /_/  __/ /\n"
           "   \\____/\\___/\\____/_____/\\____/\\__, /\\____/_/ /_/\\__,_/_/\\__, / /___/\\___/_/\n"
           "              \\             \\  /____/        \\           /____/  /\n"
           "               |_            \\ /              \\                 /\n"
           "                 \\            2                \\               /\n"
           "                  ----.                         \\             /\n"
           "                      '-,_                       4            \\\n"
           "                          `-----,                   ,-------,  \\\n"
           "                                 \\,~.      ,---^---'         |  \\\n"
           "                                     \\    /                   \\  |\n"
           "                                      \\  |                     \\_|\n"
           "                                       `-'\n\n\n")
    sys.stderr.write(art)

    # Welcome Message
    sys.stderr.write("\n   Thank you for using GeoLogonAnalyzer.py, created by David Pany at"
                     " Mandiant\n      Version 1.10\n\n")
    sys.stderr.write("   Example command syntax:\n")
    sys.stderr.write("      python GeoLogonalyzer.py --csv VPNLogs.csv --output output.csv\n\n")

    # Sleep for 1 second after welcome before showing licenses
    time.sleep(1)

    sys.stderr.write("Licenses:\n"
                     "\tThe license for GeoLogonalyzer can be found at:\n"
                     "\t\thttps://raw.githubusercontent.com/mandiant/GeoLogonalyzer/master/LICENSE.txt\n\n")

    # Attribution and license information for MaxMind
    sys.stderr.write("\tThis product includes GeoLite2 data created by MaxMind, available from\n"
                     "\thttps://www.maxmind.com\n\n")

    # Attribution and license information for Client9
    sys.stderr.write("\tThis product retrieves and operates on data including datacenter\n"
                     "\tcategorizations retrieved from https://github.com/growlfm/ipcat/\n"
                     "\twhich is a version from https://github.com/client9/ipcat/.\n"
                     "\tLicenses:\n"
                     "\t\thttps://raw.githubusercontent.com/client9/ipcat/master/LICENSE\n"
                     "\t\thttps://raw.githubusercontent.com/growlfm/ipcat/main/LICENSE\n\n")

    # Sleep for 2 seconds after displaying license
    time.sleep(2)

    #Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help='CSV like "YYYY-MM-DD HH:MM:SS,user,10.10.10.10,hostname'
                        '(optional),VPN client (optional)"', required=False)
    parser.add_argument("--custom", help='Custom line parsing to be implemented by user',
                        required=False)
    parser.add_argument("--ip_only", help='TXT file of IP Addresses only, one per line', required=False)
    parser.add_argument("--output", help='Output CSV file', required=True)
    parser.add_argument("--skip_rfc1918", help='Skip RFC1918 source IP addresses', required=False,
                        action='store_true')
    args = parser.parse_args()
    main(args)
