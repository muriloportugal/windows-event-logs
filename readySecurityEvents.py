#! py -3
# -*- coding: utf-8 -*-

#To connect at remote machine you need provide the machine_address IP or computer name, user_name (domain\\userName) and the password
#For local machine is no need to informe above parameters

# log_file could be one of 'System', 'Security', 'Application', 'Setup'. These are the most common
# Ex: If you pass log_file='Security', the script will search for all eventlogs registered at Security log.

# event_code could be None, one single value or a listof values.
# Most common is:
#   4624 successful logon,
#   4625 failed logon,
#   4634 Logoff
#   4663 File Deleted
# Ex: If you pass event_code=[4624,4625], the script will search for all successfull and failed logons.

# record_number could be None or one single value. Identifies the event within the Windows event log file. Used to get the events log most recent than the record_number informed
# Ex: if you pass record_number = 3, the script will search for all eventLogs > 3.

import wmi
import sys
import getpass
from pprint import pprint
from datetime import datetime
import time

## Class for each log object
class InsertionStrings:

  __logon_type_description = {
    '2':	"2 - Interactive (Authentication performed normally, user/password entered at system screen by keyboard.)",
    '3':	"3 - Network (A user or computer connected to this computer over the local network, like shared folder or printer)",
    '4':	"4 - Batch (Scheduled task)",
    '5':	"5 - Service (Service startup)",
    '7':	"7 - Unlock (Computer was previously locked and now was unlocked Ctrl+Alt+Del)",
    '8':	"8 - NetworkCleartext (This logon type indicates a network logon like logon type 3 but where the password was sent over the network in the clear text)",
    '9':	"9 - NewCredentials (If you use the RunAs command to start a program under a different user account)",
    '10': "10 - RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)",
    '11': "11 - CachedInteractive (If your computer is part of a domain, windows cached the credentials in case you attempt to logon when you are not connected to the organization’s network)",
  }

  def __init__ (self, req_sid, req_acc_name, req_domain, logon_type, logon_acc_name, logon_domain, proc_info_name, netw_station_name, netw_address_origin, netw_port):
    self.req_sid = req_sid
    self.req_acc_name =  req_acc_name
    self.req_domain = req_domain
    self.logon_type = self.__logon_type_description[logon_type] if (logon_type in self.__logon_type_description) else logon_type
    self.logon_acc_name = logon_acc_name
    self.logon_domain = logon_domain
    self.proc_info_name = proc_info_name
    self.netw_station_name = netw_station_name
    self.netw_address_origin = netw_address_origin
    self.netw_port = netw_port

  def __repr__(self):
    return ("\n{{"
            "\n  Security ID: {0}"
            "\n  Account Name: {1}"
            "\n  Account Domain: {2}"
            "\n  Logon Type: {3}"
            "\n  Logon Acc Name: {4}"
            "\n  Logon Domain: {5}"
            "\n  Process Name: {6}"
            "\n  Source Workstation Name: {7}"
            "\n  Source Network Address: {8}"
            "\n  Source Port: {9}"
            "\n}}").format(self.req_sid,
                        self.req_acc_name,
                        self.req_domain,
                        self.logon_type,
                        self.logon_acc_name,
                        self.logon_domain,
                        self.proc_info_name,
                        self.netw_station_name,
                        self.netw_address_origin,
                        self.netw_port)

class events_Win32_NTLogEvent:
  __event_type_description = {
    1: "1 - Error",
    2: "2 - Warning",
    4: "4 - Information",
    8: "8 - Security Audit Success",
    16: "16 - Security Audit Failure",
  }

  __event_code_description = {
    4624: "4624 - successful logon",
    4625: "4625 - failed logon",
    4634: "4634 - Logoff",
    4663: "4663 - File Deleted"
  }

  def __init__(self, computer_name, event_code, event_type, insertion_strings, log_file, record_number, time_written):
    self.computer_name = computer_name
    self.event_code = self.__event_code_description[event_code] if (event_code in self.__event_code_description) else event_code
    self.event_type = self.__event_type_description[event_type] if (event_type in self.__event_type_description) else event_type
    self.insertion_strings = insertion_strings
    self.log_file = log_file
    self.record_number = record_number
    self.time_written = time_written

def get_events(log_file, **kwargs):
  machine_address = kwargs.get('machine_address')
  user_name = kwargs.get('user_name')
  password = kwargs.get('password')
  event_code = kwargs.get('event_code')
  time_written = kwargs.get('time_written')

  # Win32_NTLogEvent parameters https://docs.microsoft.com/en-us/previous-versions/windows/desktop/eventlogprov/win32-ntlogevent
  wmi_query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='{0}'".format(log_file)

  if event_code is not None:
    if(isinstance(event_code, list)):
      for index, code in enumerate(event_code):
        if index == 0: # first event_code
          wmi_query += " AND ( EventCode="+str(code)
        else: # the rest elements of event_code list
          wmi_query += " OR EventCode="+str(code)
      # when the event_code list ends
      wmi_query += " ) "
    else:
      wmi_query += " AND EventCode="+str(event_code)

  #if record_number is not None:
    # wmi_query += " AND RecordNumber>"+str(record_number)

  if time_written != "000000000000.000000-000":
    wmi_query += " AND TimeWritten>'{0}'".format(time_written)

  print("\n"+wmi_query+"\n")

  wmi_query_results = ''
  try:
    # Initialize WMI object
    wmi_obj = wmi.WMI(machine_address, user=user_name, password=password)

    # Query WMI object.
    events_log = wmi_obj.query(wmi_query)

    for event in events_log:
  #  print(unicode(result.ComputerName)) # python 2.7
    #print(event.InsertionStrings) # python 3.0
      insertion_string = None
      if event.EventCode == 4624:
        insertion_string = InsertionStrings(event.InsertionStrings[0], #req_sid
                                            event.InsertionStrings[1],  #req_acc_name
                                            event.InsertionStrings[2],  #req_domain
                                            event.InsertionStrings[8],  #logon_type
                                            event.InsertionStrings[5],  #logon_acc_name
                                            event.InsertionStrings[6],   #logon_domain
                                            event.InsertionStrings[17],   #proc_info_name
                                            event.InsertionStrings[11],   #netw_station_name
                                            event.InsertionStrings[18],   #netw_address_origin
                                            event.InsertionStrings[19])  #netw_port
      elif event.EventCode == 4625:
        insertion_string = InsertionStrings(event.InsertionStrings[0], #req_sid
                                            event.InsertionStrings[1],  #req_acc_name
                                            event.InsertionStrings[2],  #req_domain
                                            event.InsertionStrings[10],  #logon_type
                                            event.InsertionStrings[5],  #logon_acc_name
                                            event.InsertionStrings[6],   #logon_domain
                                            event.InsertionStrings[18],   #proc_info_name
                                            event.InsertionStrings[13],   #netw_station_name
                                            event.InsertionStrings[19],   #netw_address_origin
                                            event.InsertionStrings[20])  #netw_port

      event_build = events_Win32_NTLogEvent(event.ComputerName,
                                            event.EventCode,
                                            event.EventType,
                                            insertion_string if (insertion_string is not None) else event.InsertionStrings,
                                            event.Logfile,
                                            event.RecordNumber,
                                            event.TimeWritten)
      pprint(vars(event_build))
      print("\n")
      #print(event)

  except Exception as e:
    print(e)

def monitor_events(**kwargs):
  machine_address = kwargs.get('machine_address')
  user_name = kwargs.get('user_name')
  password = kwargs.get('password')
  event_code = kwargs.get('event_code')


  try:
    # Initialize WMI object
    wmi_obj = wmi.WMI(machine_address, user=user_name, password=password)

    # Monitoring.
    watcher = wmi_obj.Win32_NTLogEvent.watch_for("creation",2,EventCode=event_code)
    while True:
      try:
        new_log = watcher(timeout_ms=10)
      except wmi.x_wmi_timed_out:
        pass
      else:
        print(new_log)

  except Exception as e:
    print(e)

def main():
  #initiate the date and time variables with current date time
  today = datetime.today()
  day = str(today.day).rjust(2,"0")
  month = str(today.month).rjust(2,"0")
  year = str(today.year)
  hour_utc = "00"
  hour = str(today.hour).rjust(2,"0")
  minute = "00"
  seconds = "00"
  # Get the system timezone considering daylight saving DST.
  offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
  system_timezone = offset / -(60*60)

  text_remote = "Enter remote computer name (No need for local machine): "
  text_user = "Enter with user name (Ex: domain\\user) (No need for local machine): "
  text_pwd  = "Enter password (No need for local machine): "
  text_date = "Enter the date of event (format dd/mm/YYYY, default current date {0}/{1}/{2}): ".format(day,month,year)
  text_time = "Enter the time of event (format hh:mm:ss, default current hour {0}:00:00): ".format(hour)
  text_mode = "Choose mode (1 - Monitoring new logs or 2 - Search old logs): "
  text_event_code = ("Enter the event code, most common is:"
                    "\n4624 - 'successful logon',"
                    "\n4625 - 'failed logon'(Default),"
                    "\n4634 - 'logoff',"
                    "\n4663 - 'file Deleted'."
                    "\nSeparate each value with comma for multiple select: ")

  if sys.version_info.major == 2:
    print('python2')
    remote = raw_input(text_remote)
    user = raw_input(text_user)
    pwd = getpass.getpass(prompt=text_pwd)
    event_code = raw_input(text_event_code)
    mode = raw_input(text_mode)
    if mode == "1":
      print('teste')
    elif mode == "2":
      date = raw_input(text_date)
      if len(date) > 0:
        day, month, year = date.split('/')
      event_time = raw_input(text_time)
      if len(event_time) > 0:
        hour, minute, seconds = event_time.split(':')
      hour_utc = int(hour)-int(system_timezone) #convert to UTC time
      event_time = year+month+day+str(hour_utc).rjust(2,'0')+minute+seconds+".000000-000"

  elif sys.version_info.major == 3:
    print('python3')
    remote = input(text_remote)
    user = input(text_user)
    pwd = getpass.getpass(prompt=text_pwd)
    event_code = input(text_event_code)
    mode = input(text_mode)
    if mode == "1":
      print('teste')
    elif mode == "2":
      date = input(text_date)
      if len(date) > 0:
        day, month, year = date.split('/')
      event_time = input(text_time)
      if len(event_time) > 0:
        hour, minute, seconds = event_time.split(':')
      hour_utc = int(hour)-int(system_timezone)#convert to UTC time
      event_time = year+month+day+str(hour_utc).rjust(2,'0')+minute+seconds+".000000-000"

  if len(event_code) <= 0:
    event_code = "4625" #failed logon
  event_code_list = event_code.split(',')

  if mode == "1":
    events = monitor_events(machine_address=remote,
                            user_name=user,
                            password=pwd,
                            event_code=event_code)
  elif mode == "2":
    events = get_events("Security",
                        machine_address=remote,
                        user_name=user,
                        password=pwd,
                        event_code=event_code_list,
                        time_written=event_time)
  else:
    print("mode {0} is not accepted".format(mode))


if __name__ == '__main__':
  main()
