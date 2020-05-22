#! py -3
# -*- coding: utf-8 -*-

#To connect at remote machine you need provide the machine_address IP or computer name, user_name (domain\\userName) and the password
#For local machine is no need to informe above parameters

# log_file could be one of 'System', 'Security', 'Application', 'Setup'. These are the most common
# Ex: If you pass log_file='Security', the script will search for all eventlogs registered at Security log.

# event_code could be None, one single value or a listof values.
# Most common are:
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

## Class for each log object
class InsertionStrings:
  def __init__ (self, req_sid, req_acc_name, req_domain, logon_type, logon_acc_name, logon_domain, proc_info_name, netw_station_name, netw_address_origin, netw_port):
    self.req_sid = req_sid
    self.req_acc_name =  req_acc_name
    self.req_domain = req_domain
    self.logon_type = logon_type
    self.logon_acc_name = logon_acc_name
    self.logon_domain = logon_domain
    self.proc_info_name = proc_info_name
    self.netw_station_name = netw_station_name
    self.netw_address_origin = netw_address_origin
    self.netw_port = netw_port

  def __repr__(self):
    return ("\nInsertionStrings {{"
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

def get_events(log_file, **kwargs):
  machine_address = kwargs.get('machine_address')
  user_name = kwargs.get('user_name')
  password = kwargs.get('password')
  event_code = kwargs.get('event_code')
  record_number = kwargs.get('record_number')
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

  print(wmi_query)

  wmi_query_results = ''
  try:
    # Initialize WMI object
    print(machine_address + ' ' + user_name + ' ' + password)
    wmi_obj = wmi.WMI(machine_address, user=user_name, password=password)

    # Query WMI object.
    events_log = wmi_obj.query(wmi_query)

    for event in events_log:
  #  print(unicode(result.ComputerName)) # python 2.7
    #print(event.InsertionStrings) # python 3.0
      teste = InsertionStrings(event.InsertionStrings[0], #req_sid
                              event.InsertionStrings[1],  #req_acc_name
                              event.InsertionStrings[2],  #req_domain
                              event.InsertionStrings[8],  #logon_type
                              event.InsertionStrings[5],  #logon_acc_name
                              event.InsertionStrings[6],   #logon_domain
                              event.InsertionStrings[17],   #proc_info_name
                              event.InsertionStrings[11],   #netw_station_name
                              event.InsertionStrings[18],   #netw_address_origin
                              event.InsertionStrings[19])  #netw_port
      print(teste)

  except Exception as e:
    print(e)


def monitor_events(**kwargs):
  machine_address = kwargs.get('machine_address')
  user_name = kwargs.get('user_name')
  password = kwargs.get('password')

  try:
    # Initialize WMI object
    wmi_obj = wmi.WMI(machine_address, user=user_name, password=password)

    # Monitoring.
    watcher = wmi_obj.Win32_NTLogEvent.watch_for("creation",2,EventCode=4624)
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
  #initiate the time variables
  day = '00'
  month = '00'
  year = '00'
  hour_utc = '00'
  minute = '00'
  seconds = '00'

  text_remote = "Enter remote computer name (No need for local machine): "
  text_user = "Enter with user name (Ex: domain\\user) (No need for local machine): "
  text_pwd  = "Enter password (No need for local machine): "
  text_date = "Enter the date of event (format dd/mm/YYYY): "
  text_time = "Enter the time of event (format hh:mm:ss): "
  text_mode = "Choose mode (1 - Monitoring new logs or 2 - Search old logs): "

  if sys.version_info.major == 2:
    print('python2')
    remote = raw_input(text_remote)
    user = raw_input(text_user)
    pwd = getpass.getpass(prompt=text_pwd)
    date = raw_input(text_date)
    if len(date) > 0:
      day, month, year = date.split('/')
      time = raw_input(text_time)
      if len(time) > 0:
        hour, minute, seconds = time.split(':')
        hour_utc = int(hour)+3
    event_time = year+month+day+str(hour_utc).rjust(2,'0')+minute+seconds+".000000-000"
    mode = raw_input(text_mode)

  elif sys.version_info.major == 3:
    print('python3')
    remote = input(text_remote)
    user = input(text_user)
    pwd = getpass.getpass(prompt=text_pwd)
    date = input(text_date)
    if len(date) > 0:
      day, month, year = date.split('/')
      time = input(text_time)
      if len(time) > 0:
        hour, minute, seconds = time.split(':')
        hour_utc = int(hour)+3
    event_time = year+month+day+str(hour_utc).rjust(2,'0')+minute+seconds+".000000-000"
    mode = input(text_mode)

  #events = get_events("Security", machine_address=remote, user_name=user, password=pwd, event_code=4658,record_number=617206620)
  if mode == "1":
    events = monitor_events(machine_address=remote,
                            user_name=user,
                            password=pwd)
  elif mode == "2":
    events = get_events("Security",
                        machine_address=remote,
                        user_name=user,
                        password=pwd,
                        event_code=4624,
                        record_number=153332318,
                        time_written=event_time)
  else:
    print("mode {0} is not accepted".format(mode))



if __name__ == '__main__':
  main()
