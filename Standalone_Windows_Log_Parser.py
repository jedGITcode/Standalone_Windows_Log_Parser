#python
################################################################################
# Standalone Windows log parser with graphical review
# Tools: Powershell for log copy and rotation
#      : Python
#              : Plotly
#              : Pandas
#
#      : Reference
#         
#   nsacyber/Event-Forwarding-Guidance
#   https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events
#
#   Some logs/log locations may not be available on all system.
#   A commented out function for enabling logged is included.   
#  
#   report_base must be set before first run !!!!!!!
#   Copy Results must be uncommented to use. 
#
#   Author: Justin E Davis  2020    Justin Davis AT jedconsulting DOT net
#
################################################################################

################################################################################
# Imports
################################################################################
import plotly.graph_objects as go
import plotly.express as px
import plotly as py
from plotly.subplots import make_subplots

import subprocess as sub
import pandas as pd
from pandas.tseries.holiday import USFederalHolidayCalendar
import numpy as np
import datetime
import re
import os
from shutil import copytree

################################################################################
# Variables
################################################################################
# Date
date = str(datetime.date.today())

# Holidays
cal = USFederalHolidayCalendar()
holidays = cal.holidays(start='2020-01-01', end='2031-01-01').to_pydatetime()

# Computer Name
CN = os.environ['COMPUTERNAME']

# Report Directory Base
#!!!!!!!!!!!!!!!!!!!
#!  Must Set !!!!!
#!!!!!!!!!!!!!!!!!!!
####report_base = ""

# Report Directory
report_dir = report_base + date + "\\" + CN + "\\"
# Report logs
report_log = "reportlog.txt"

# Reports Name: Report Dictionary
reports = {}

# Logs to backup/rotate/search
logs = ['Application', 'Microsoft-Windows-Application-Experience/Program-Inventory'
, 'Microsoft-Windows-AppLocker/EXE and DLL'
, 'Microsoft-Windows-AppLocker/MSI and Script'
, 'Microsoft-Windows-AppLocker/Packaged app-Deployment'
, 'Microsoft-Windows-AppLocker/Packaged app-Execution'
, 'Microsoft-Windows-CAPI2/Operational'
, 'Microsoft-Windows-CertificationAuthority'
, 'Microsoft-Windows-CodeIntegrity/Operational'
, 'Microsoft-Windows-DNS-Client/Operational'
, 'Microsoft-Windows-DNSServer/Analytical'
, 'Microsoft-Windows-Kernel-PnP/Device Configuration'
, 'Microsoft-Windows-LSA/Operational'
, 'Microsoft-Windows-NetworkProfile/Operational'
, 'Microsoft-Windows-Powershell/Operational'
, 'Microsoft-Windows-PrintService/Operational'
, 'Microsoft-Windows-TaskScheduler/Operational'
, 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
, 'Microsoft-Windows-USB-USBHUB3-Analytic'
, 'Microsoft-Windows-Windows Defender/Operational'
, 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
, 'Microsoft-Windows-WindowsUpdateClient/Operational'
, 'Microsoft-Windows-WLAN-AutoConfig/Operational'
, 'Powershell'
, 'RemoteAccess'
, 'Security'
, 'Setup'
, 'System'
, 'User32']


################################################################################
# Create log directory
################################################################################
if not os.path.exists(report_dir):
    os.makedirs(report_dir)


################################################################################
# Enable logging 
#      Turn on if not already, need for new systems and any updates that
#      would default the logs off. 
################################################################################
def enable_logging(logs):
    for log in logs:
        call = sub.Popen(["powershell", "WEVTUTIL SL \"" + log + "\" /e:true"]
                        , stdout=sub.PIPE)
        result, err = call.communicate()


################################################################################
# Backup Logs, Copy and clear system logs
#      Args:
#            Logs: list of log files to backup and clear
################################################################################
def backup_logs(logs):
    for log in logs:
        call = sub.Popen(["powershell", "WEVTUTIL CL \"" + log + "\" /BU:" 
               + report_dir + log.replace("/", "-") + ".evtx"], stdout=sub.PIPE)
        result, err = call.communicate()


################################################################################
# Is off hours
#      Args:
#           EventDate     
################################################################################
def is_off_hours(EventDate):
    dt = datetime.datetime.strptime(EventDate[:-4],
                '%Y-%m-%dT%H:%M:%S')
    dd = datetime.datetime.strptime(EventDate[:-13],
                '%Y-%m-%d')            
    if dt.isoweekday() not in range(1,6) or dt.hour not in range(7,18
                ) or dd in holidays:
        return True
    else:
        return False

################################################################################
# Query log file for event(s)
#     Args:
#          eventIDs: list of strings of event ids exp ['4624', '4625']
#          logFile : System logs to search
#     Notes: Max of 23 events at one, this is a observation from testing
################################################################################
def query_events(eventIDs, logFile):
    if len(eventIDs) > 23:
        print("***************************")
        print("Query event list too large > 23")
        print("***************************")
        exit()
    # Variables
    queryString = ''
    first = True
    # Build search query
    for eventID in eventIDs:
        if first is False:
            queryString += " or (EventID=" + eventID + ")"
        else:
            queryString += "(EventID=" + eventID + ")"
            first = False
    # Call powershell to query log file
    call = sub.Popen(["powershell", "WEVTUTIL qe /rd:true /c:99999 /lf:true "
                      + "/f:text " + logFile.replace("/", "-") + ".evtx /q:\"*[System[ " + queryString
                      + "] ]\" "], stdout=sub.PIPE)
    result, err = call.communicate()
    # cp1252 resolves windows chars
    return result.decode('cp1252')

################################################################################
# Process events into reviewable log and interactive graphs
#     Args:
#          result:  Results of a log query
#          name:    Name of query
#          offhours: Boolean, limit to only off hour results
#          localsystem: Boolean Limit to only local accounts with CN
################################################################################
def process_logs(result, name, offhours, localsystem):
    # Variables
    EventID = ''
    EventDate = ''
    EventDescription = ''
    EventSecurityID = ''
    EventAccount = ''
    EventAccountAlt = ''
    EventLogonID = ''
    EventLogonType = ''
    EventDomain = ''
    EventReason = ''
    ObjectName = ''
    AccessObject = False
    GetNextLine = False
    ProcessCommandLine = ''
    dates = []
    users = []
    reason = []
    titlebuf = [] # List of Dictionary's
    title = ''
    
    f = open(report_dir + report_log, "a")
    f.write("\n\n" + name + "\n")
    f.write("--------------------------------------------------------------\n")
    
    for line in result.splitlines():
        
        if "Event[" in line:
            # Print/Write the log line if not the first record
            if int(re.split('\[|\]', line)[1]) > 0:
                skip_check = True
                # limit to off hours only check
                if offhours:
                    skip_check = False
                    if is_off_hours(EventDate):
                        skip_check = True
                # limit to local system
                if localsystem and skip_check:
                    if EventDomain != CN:
                        skip_check = False
                if skip_check:
                    erata = ''
                    dates.append(EventDate)
                    if EventAccount != '':
                        users.append(EventDomain + '\\' + EventAccount)
                    else:
                        users.append(EventAccountAlt)
                        EventAccount = EventAccountAlt
                    titlebuf.append({'id':EventID, 'Desc':EventDescription})
                    if AccessObject:
                        reason.append(ObjectName)
                        erata = "File:" + ObjectName
                    elif EventReason != '':
                        reason.append(EventReason)
                    else:
                        reason.append(EventDescription)
                    f.write(EventID + " " + EventDate + " " + EventDescription
                        + " " + EventSecurityID + " " + EventAccount + " "
                        +  EventLogonID + " " +  EventLogonType + " "
                        + EventDomain  + " " + EventReason + ProcessCommandLine + erata +"\n")
                # New event rest buffers
                EventID = ''
                EventDate = ''
                EventDescription = ''
                EventSecurityID = ''
                EventAccount = ''
                EventAccountAlt = ''
                EventLogonID = ''
                EventLogonType = ''
                EventDomain = ''
                EventReason = ''
                ObjectName = ''
                AccessObject = False
                ProcessCommandLine = ''
                
        if "Event ID:" in str(line):
            EventID = str(line).replace(" ", "").split(':', 1)[1]
        if "Date:" in str(line):
            EventDate = str(line).replace(" ", "").split(':', 1)[1]
        if GetNextLine is True:
            EventDescription = str(line)
            GetNextLine = False
        if "Description:" in str(line):
            # Get next line as Description
            GetNextLine = True
        if "Security ID:" in str(line):
            EventSecurityID = str(line).replace(" ", "").split(':', 1)[1]
        if "Account Name:" in str(line):
            if "Network " not in str(line):
                EventAccount = str(line).replace(" ", "").replace("\t", "").split(':', 1)[1]
        if "User Name:" in str(line):
            EventAccountAlt = str(line).replace(" ", "").replace("\t", "").split(':', 1)[1]
        if "Logon ID:" in str(line):
            EventLogonID = str(line).replace(" ", "").split(':', 1)[1]
        if "Account Domain:" in str(line):
            if "Network " not in str(line):
                EventDomain = str(line).replace(" ", "").replace("\t",'').split(':', 1)[1]
        if " Reason:" in str(line):
            EventReason = str(line).split(':', 1)[1]
        if "Object Name:" in str(line):
            ObjectName = str(line).split(':', 1)[1]
        if "Access" in str(line) and "WriteData" in str(line) and ObjectName != '':
            AccessObject = True
        if "Process Command Line:" in str(line):
            ProcessCommandLine = str(line).split(':', 1)[1]
        # Print/Write the last log line record
    
    skip_check = True
    # limit to off hours only check
    if offhours:
        skip_check = False
        if is_off_hours(EventDate):
            skip_check = True
    # limit to local system
    if localsystem and skip_check:
        if EventDomain != CN:
            skip_check = False
    if skip_check:
        if EventID != '':
            erata = ''
            dates.append(EventDate)
            if EventAccount != '':
                users.append(EventDomain + '\\' + EventAccount)
            else:
                users.append(EventAccountAlt)
                EventAccount = EventAccountAlt
            titlebuf.append({'id':EventID, 'Desc':EventDescription})
            if AccessObject:
                reason.append(ObjectName)
                erata = "File:" + ObjectName
            elif EventReason != '':
                reason.append(EventReason)
            else:
                reason.append(EventDescription)
            f.write(EventID + " " + EventDate + " " + EventDescription + " "
                + EventSecurityID + " " + EventAccount + " " +  EventLogonID
                + " " +  EventLogonType + " " + EventDomain  + " "
                + EventReason + ProcessCommandLine + erata + "\n")
    f.close()
    data1 = {'Dates': dates, 'Users':users, 'Reason': reason}
    df = pd.DataFrame.from_dict(data1)
    graph1 = px.scatter(df, x="Dates", y="Users", color='Reason',
                        hover_data=['Reason'])
    
    #Remove duplicate ID's
    titlebuf = list({list['id']:list for list in titlebuf}.values())
    for t in titlebuf:
        title += t['id'] + " " + t['Desc'] + "<br>"
        graph1.update_layout(title=title)
    return graph1


################################################################################
# Report On Events
#     Args:
#          Events
#          Report Name
#          Log to search by Name
#          Offhours Boolean to limit by off hours
#          Localsystem Boolean to limit to local system accounts
################################################################################
def report_on(events, name, syslog, offhours, localsystem):
    result = query_events(events, report_dir + syslog)
    if result != '':
        result_processed = process_logs(result, name, offhours, localsystem)
        result_processed.write_html(report_dir + name +".html")
        reports.update( {name:result_processed} )


################################################################################
# HTML Summary Report
#     Args Global : 
#                  Reports
################################################################################
def html_summary_report():
    f = open(report_dir + "summary_report.html", "w")
    f.write("<html><head><title>Summary Report " + date +"</title></head><body>")
    f.write("<h1>Summary Report " + date +"</h1>")
    for report in reports:
        f.write("<br/><h1>" + report + "</h1><br/>")
        f.write("<p>-----------------------------------------------------</p>")
        f.write("<iframe src=\"" + report +".html\" ")
        f.write("height=\"100%\" width=\"100%\"></iframe>")
    f.write("</body></html>")
    f.close()




################################################################################
################################################################################
################################################################################
################################################################################
# Events
################################################################################
################################################################################
################################################################################

################################################################################
# Enable Logging
################################################################################
#enable_logging(logs)


################################################################################
# Backup and Clear log files
################################################################################
backup_logs(logs)



################################################################################
# Account Usage
#      4740, 4625, 4634, 4624, 4725, 4767, 4648, 4672, 4723, 4647
#      Security
################################################################################
name = "Account_Usage"
log = "security" 
events = ['4740', '4625', '4634', '4624', '4725', '4767', '4648', 
          '4672', '4723', '4647' ]
report_on(events, name, log, False, False)
################################################################################
# Account Usage Local Accounts Only
name = "Account_Usage_Local_Accounts" 
report_on(events, name, log, False, True)
################################################################################
# Account Usage Off Hours
name = "Account_Usage_Off_Hours" 
report_on(events, name, log, True, False)
################################################################################
# Account Usage Off Hours Local Accounts Only
name = "Account_Usage_Off_Hours_Local_Accounts" 
report_on(events, name, log,True, True)

################################################################################
# Account Usage Management
#      4781, 4733, 1518, 4776, 5376, 5377, 4720, 4722, 4782, 4731, 4735, 4726, 
#      4728, 4732, 4756, 4704, 4793, 4766, 4765
#      Security
################################################################################
name = "Account_Usage_Management"
log = "security"
events = ['4781', '4733', '1518', '4776', '5376', '5377', '4720', '4722', 
          '4782', '4731', '4735', '4726', '4728', '4732', '4756', '4704', 
          '4793', '4766', '4765']
report_on(events, name, log, False, False)
################################################################################
# Account Usage Management Off Hours
name = "Account_Usage_Management_Off_Hours" 
report_on(events, name, log,True, False)
################################################################################
# Account Usage Management  Off Hours local accounts only
name = "Account_Usage_Management_Off_Hours_Local_Accounts" 
report_on(events, name, log,True, True)

################################################################################
# Account Usage Application
#      1518, 1511
#      Application
################################################################################
name = "Account_Usage_Application"
log = "Application" 
events = ['1518', '1511']
report_on(events, name, log, False, False)

################################################################################
# Account Usage Local Security Authority
#      1518, 1511
#      Application
################################################################################
name = "Account_Usage_Local_Security_Authority"
log = "Microsoft-Windows-LSA/Operational" 
events = ['300']
report_on(events, name, log, False, False)

################################################################################
# Write Removable Media
#      4656
#      Security
################################################################################
name = "Write_Removable_Media"
log = "security"
events = ['4656']
report_on(events, name, log, False, False)

################################################################################
# Registry Change
#      4657
#      Security
################################################################################
name = "Registry_Change"
log = "security"
events = ['4657']
report_on(events, name, log, False, False)

################################################################################
# Object Access
#      4662, 4663
#      Security
################################################################################
name = "Object_Access"
log = "security"
events = ['4662', '4663']
report_on(events, name, log, False, False)

################################################################################
# External Media Detection
#      400, 410
#      Microsoft-Windows-Kernel-PnP/Device Configuration
################################################################################
name = "External_Media_Detection"
log = "Microsoft-Windows-Kernel-PnP/Device Configuration"
events = ['400', '410']
report_on(events, name, log, False, False)

################################################################################
# External Media Detection USB
#      43
#      Microsoft-Windows-USB-USBHUB3-Analytic
################################################################################
name = "External_Media_Detection_USB"
log = "Microsoft-Windows-USB-USBHUB3-Analytic"
events = ['43']
report_on(events, name, log, False, False)

################################################################################
# Printing Services
#      307
#     Microsoft-Windows-PrintService/Operational 
################################################################################
name = "Printing_Services"
log = "Microsoft-Windows-PrintService/Operational"
events = ['307']
report_on(events, name, log, False, False)

################################################################################
# Windows Update Errors
#      20,24,25,31,34,35,1009
#      Microsoft-Windows-WindowsUpdateClient/Operational
################################################################################
name = "Windows_Update_Errors"
log = "Microsoft-Windows-WindowsUpdateClient/Operational"
events = ['20', '24', '25', '31', '34', '35', '1009']
report_on(events, name, log, False, False)

################################################################################
# Windows Firewall
#      2004,2005,2006,2009,2033
#      Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
################################################################################
name = "Windows_Firewall"
log = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
events = ['2004','2005','2006',   '2009', '2033']
report_on(events, name, log, False, False)

################################################################################
# Windows Defender
#      1005,1006,1007,1008,1009,1010,1116,11117,1118,1119,2001,2003,2004,3002,
#      5008
#      Microsoft-Windows-Windows Defender/Operational
################################################################################
name = "Windows_Defender"
log = "Microsoft-Windows-Windows Defender/Operational"
events = ['1005', '1006', '1007', '1008', '1009', '1010', '1116', '11117',
          '1118', '1119', '2001', '2003', '2004', '3002', '5008']
report_on(events, name, log, False, False)

################################################################################
# Task Scheduler Activities
#      106,141,142,200
#      Microsoft-Windows-TaskScheduler/Operational
################################################################################
name = "Task_Scheduler_Activities"
log = "Microsoft-Windows-TaskScheduler/Operational"
events = ['106', '141', '142', '200']
report_on(events, name, log, False, False)

################################################################################
# System or Service Failures
#      7022, 7023, 7024, 7026, 7031, 7032, 7034
#      System
################################################################################
name = "System_or_Service_Failures"
log = "System"
events = ['7022', '7023', '7024', '7026', '7031', '7032', '7034']
report_on(events, name, log, False, False)

################################################################################
# System Integrity Registry
#      4657
#      Security
################################################################################
name = "System_Integrity_Registry"
log = "Security"
events = ['4657']
report_on(events, name, log, False, False)

################################################################################
# System Integrity time
#      1
#      System
################################################################################
name = "System_Integrity_Time"
log = "System"
events = ['1']
report_on(events, name, log, False, False)

################################################################################
# Software and Service Installation Inventory
#      800, 903, 904, 905, 906, 907, 908
#      Microsoft-Windows-Application-Experience/Program-Inventory
################################################################################
name = "Software_and_Service_Installation_Inventory"
log = "Microsoft-Windows-Application-Experience/Program-Inventory"
events = ['800', '903', '904', '905', '906', '907', '908']
report_on(events, name, log, False, False)

################################################################################
# Software and Service Installation System
#      6, 19, 7000, 7045
#      System
################################################################################
name = "Software_and_Service_Installation_System"
log = "System"
events = ['6', '19', '7000','7045']
report_on(events, name, log, False, False)

################################################################################
# Software and Service Installation Application
#      1022, 1033
#      Application
################################################################################
name = "Software_and_Service_Installation_Application"
log = "Application"
events = ['1022', '1033']
report_on(events, name, log, False, False)

################################################################################
# Software Updates
#      2, 1009
#      Setup
################################################################################
name = "Software_Updates"
log = "Setup"
events = ['2', '1009']
report_on(events, name, log, False, False)

################################################################################
# PowerShell Activities
#      4103, 4104, 4105, 4106
#      Microsoft-Windows-Powershell/Operational
################################################################################
name = "PowerShell_Activities"
log = "Microsoft-Windows-Powershell/Operational"
events = ['4103', '4104', '4105', '4106']
report_on(events, name, log, False, False)

################################################################################
# PowerShell Remote Connection
#      169, 800
#      Powershell
################################################################################
name = "PowerShell_Remote"
log = "Powershell"
events = ['169', '800']
report_on(events, name, log, False, False)

################################################################################
# Network Policy Server Security
#      4706, 4713, 4714, 4716, 4719, 4769, 4778, 4779, 4897, 5140, 5142, 5144, 
#      5145, 5632, 6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280
#      Security
################################################################################
name = "Network_Policy_Server_Security"
log = "Security"
events = ['4706', '4713', '4714', '4716', '4719', '4769', '4778', '4779', 
          '4897', '5140', '5142', '5144', '5145', '5632', '6272', '6273', 
          '6274', '6275', '6276', '6277', '6278', '6279', '6280']
report_on(events, name, log, False, False)

################################################################################
# Network Policy Remote Access
#      20250, 20274, 20275
#      RemoteAccess
################################################################################
name = "Network_Policy_Remote_Access"
log = "RemoteAccess"
events = ['20250', '20274', '20275']
report_on(events, name, log, False, False)

################################################################################
# Network Policy Terminal Service
#      1024
#      Microsoft-Windows-TerminalServices-RDPClient/Operational
################################################################################
name = "Network_Policy_Terminal_Service"
log = "Microsoft-Windows-TerminalServices-RDPClient/Operational"
events = ['1024']
report_on(events, name, log, False, False)

################################################################################
# Mobile Device Activities
#      8003, 10000, 10001, 8000, 8011, 8001, 11000, 11001, 11002, 12011, 
#      12012, 12013, 8002, 11004, 11005, 11010, 11006
#      Microsoft-Windows-WLAN-AutoConfig/Operational
################################################################################
name = "Mobile_Device_Activities"
log = "Microsoft-Windows-WLAN-AutoConfig/Operational"
events = ['8003', '8000', '8011', '8001', '11000', '11001', '11002', '12011' 
          '12012', '12013', '8002', '11004', '11005', '11010', '11006']
report_on(events, name, log, False, False)

################################################################################
# Mobile Device Activities Network
#      10000, 10001
#      Microsoft-Windows-WLAN-AutoConfig/Operational
################################################################################
name = "Mobile_Device_Activities_Network"
log = "Microsoft-Windows-WLAN-AutoConfig/Operational"
events = ['10000', '10001']
report_on(events, name, log, False, False)

################################################################################
# Microsoft Cryptography API
#      11, 70, 90
#      Microsoft-Windows-CAPI2/Operational
################################################################################
name = "Microsoft_Cryptography_API"
log = "Microsoft-Windows-CAPI2/Operational"
events = ['11', '70', '90']
report_on(events, name, log, False, False)

################################################################################
# Kernel Driver Signing System
#      219
#      System
################################################################################
name = "Kernel_Driver_Signing_System"
log = "System"
events = ['219']
report_on(events, name, log, False, False)

################################################################################
# Kernel Driver Signing Security
#      5038, 6281
#      Security
################################################################################
name = "Kernel_Driver_Signing_Security"
log = "Security"
events = ['5038', '6281']
report_on(events, name, log, False, False)

################################################################################
# Kernel Driver Signing CodeIntegrity
#      3001, 3002, 3003, 3004, 3010, 3023
#      Microsoft-Windows-CodeIntegrity/Operational
################################################################################
name = "Kernel_Driver_Signing_CodeIntegrity"
log = "Microsoft-Windows-CodeIntegrity/Operational"
events = ['3001', '3002', '3003', '3004', '3010', '3023']
report_on(events, name, log, False, False)

################################################################################
# Group Policy Errors
#      1125, 1126, 1129
#      System
################################################################################
name = "Group_Policy_Errors"
log = "System"
events = ['1125', '1126', '1129']
report_on(events, name, log, False, False)

################################################################################
# DNS/Directory Services Security
#      5137, 5141, 5136, 5139, 5138
#      
################################################################################
name = "DNS_Directory_Services_Security"
log = "Security"
events = ['5137', '5141', '5136', '5139', '5138']
report_on(events, name, log, False, False)

################################################################################
# DNS/Directory Services DNS Server
#      256, 257
#      Microsoft-Windows-DNSServer/Analytical
################################################################################
name = "DNS_Directory_Services_Server"
log = "Microsoft-Windows-DNSServer/Analytical"
events = ['256', '257']
report_on(events, name, log, False, False)

################################################################################
# DNS/Directory Services Client
#      3008, 3020
#      Microsoft-Windows-DNS-Client/Operational
################################################################################
name = "DNS_Directory_Services"
log = "Microsoft-Windows-DNS-Client/Operational"
events = ['3008', '3020']
report_on(events, name, log, False, False)

################################################################################
# Clearing Event Logs System
#      104
#      System
################################################################################
name = "Clearing_Event_Logs_System"
log = "System"
events = ['104']
report_on(events, name, log, False, False)

################################################################################
# Clearing Event Logs Security
#      1102, 1100
#      Security
################################################################################
name = "Clearing_Event_Logs_Security"
log = "Security"
events = ['1100', '1102']
report_on(events, name, log, False, False)

################################################################################
# Certificate Services Security
#      90, 4886, 4890, 4874, 4873, 4870, 4887, 4885, 4891, 4888, 4898, 4882, 
#      4892, 4880, 4881, 4900, 4899, 4896
#      Microsoft-Windows-CertificationAuthority
################################################################################
name = "Certificate_Services_CA"
log = "Microsoft-Windows-CertificationAuthority"
events = ['90']
report_on(events, name, log, False, False)

################################################################################
# Certificate Services Security
#      90, 4886, 4890, 4874, 4873, 4870, 4887, 4885, 4891, 4888, 4898, 4882, 
#      4892, 4880, 4881, 4900, 4899, 4896
#      
################################################################################
name = "Certificate_Services_Security"
log = "Security"
events = ['4886', '4890', '4874', '4873', '4870', '4887', '4885', '4891', 
          '4888', '4898', '4882', '4892', '4880', '4881', '4900', '4899', 
          '4896']
report_on(events, name, log, False, False)

################################################################################
# Boot Events User32
#      1074
#      
################################################################################
name = "Boot_Events_User32"
log = "User32"
events = ['1074']
report_on(events, name, log, False, False)

################################################################################
# Boot Events System
#      12, 13
#      
################################################################################
name = "Boot_Events_System"
log = "System"
events = ['12', '13']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting Security
#      4688, 4689
#      Security
################################################################################
name = "Application_Whitelisting_Security"
log = "Security"
events = ['4688', '4689']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting app-Execution
#      8020
#      Microsoft-Windows-AppLocker/Packaged app-Execution
################################################################################
name = "Application_Whitelisting_App_Execution"
log = "Microsoft-Windows-AppLocker/Packaged app-Execution"
events = ['8020']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting app-Deployment
#      8023
#      Microsoft-Windows-AppLocker/Packaged app-Deployment
################################################################################
name = "Application_Whitelisting_App_Deployment"
log = "Microsoft-Windows-AppLocker/Packaged app-Deployment"
events = ['8023']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting MSI
#      8006, 8007, 8005
#      Microsoft-Windows-AppLocker/MSI and Script
################################################################################
name = "Application_Whitelisting_MSI"
log = "Microsoft-Windows-AppLocker/MSI and Script"
events = ['8006', '8007', '8005']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting EXE and DLL
#      8006, 8007, 8005
#      Microsoft-Windows-AppLocker/EXE and DLL
################################################################################
name = "Application_Whitelisting_EXE_DLL"
log = "Microsoft-Windows-AppLocker/EXE and DLL"
events = ['8002', '8003', '8004']
report_on(events, name, log, False, False)

################################################################################
# Application Whitelisting Application
#      865, 866, 867, 868, 882
#      Application
################################################################################
name = "Application_Whitelisting_Application"
log = "Application"
events = ['865', '866', '867', '868', '882']
report_on(events, name, log, False, False)

################################################################################
# Application Crashes
#      1000, 1001, 1002
#      Application
################################################################################
name = "Application_Crashes"
log = "Application"
events = ['1000', '1001', '1002']
report_on(events, name, log, False, False)

################################################################################
# Application Crashes System
#      1001
#      System
################################################################################
name = "Application_Crashes_System"
log = "System"
events = ['1001']
report_on(events, name, log, False, False)

################################################################################
# Generate Summary HTML
################################################################################
html_summary_report()

################################################################################
# Copy Results
# Uncomment and set Paths !!!!!!!!!!!!!!!!!!!
################################################################################
# Create Directory
#if not os.path.exists( r"\\NetworkPath\\" + date.split('-')[0] + "\\" + date ):
#    os.makedirs(r"\\NetworkPath\\" + date.split('-')[0] + "\\" + date)

#Move Files
#copytree(report_dir + date + "\\" + CN, r"\\NetworkPath\\" + date.split('-')[0] 
#         + "\\" + date + "\\" + CN )
