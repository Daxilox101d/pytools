#===============================INFO:========================================
#This simple script is used to get the process id of any process in windows
#============================================================================

import psutil

Process_Name = input("Input The Process Name: ").lower()
PID = None
for proc in psutil.process_iter(['pid','name']):
    if Process_Name in proc.info['name'].lower():
      PID = proc.info['pid']
      break
if PID:
  print(f"The Process Is Found! \n\tProcess Name: {proc.info['name']} \n\tPID: {PID}")
else:
  print("Process Not Found")
