import time

from ppadb.client import Client as AdbClient
import re
import os
import csv
import frida
#Applications folder
path = 'F:/automatization/app'
#Tested Applications folder
path1='F:/automatization/app3'
#Path to monkeyrunner
android_home=r'C:\Users\alime\AppData\Local\Android\Sdk\tools\bin\monkeyrunner.bat'

#Connecting for a device
def connect():
    client = AdbClient(host="127.0.0.1", port=5037) # Default is "127.0.0.1" and 5037
    devices = client.devices()
    if len(devices) == 0:
        print('No devices')
        quit()
    device = devices[0]
    print(f'Connected to {device}')
    return device, client


def search_package_in_avd(device):
    command = device.shell('pm list packages -3 '+'|cut -f 2 -d '+':')
    packages=re.split(':|\r|\n',command)
    for package in packages:
     print(package+"\n")
    if not packages:
        return ""
    else:
        return packages
        
def read_files():
    input_list=[]
    file = open("results3.csv")  
    reader = csv.reader(file)
    #gets all apk file names
    files = os.listdir(path)
    
    for row in reader:
       if len(row)>0:
        input_list.append(row)
    file.close()    
    return files

def install_package(package):
    try:
     device.install(path+'/'+package)
     print(package+" installed ")
     return True
    except Exception as e:
     print("Error"+str(e))
     try:
      os.remove(path+"/"+package)
     except Exception as e:
      print("Error"+str(e))     
     return False
    
def uninstall_package(device):
     packages=search_package_in_avd(device)
     for package in packages:
        device.uninstall(package)
        print(package+" uninstalled")

def file_open():
    header = ["packageName","package","header","method","url","useragent"]
    file = open('eval1.csv', 'a')
    writer = csv.writer(file)
   
    writer.writerow(header)    
    return file,writer

def file_open1():
    file = open('eval1.csv', 'a')
    writer = csv.writer(file)
    return file,writer    
    
def add_rows(writer,data):
    writer.writerow(data)

      
def frida_instument():
  try:
    device_frida = frida.get_usb_device()
    f_package=search_package_in_avd(device)[0];
    pid = device_frida.spawn([f_package])
    session = device_frida.attach(pid)
    script = session.create_script(open("ev.js").read())
    script.on("message", on_message)
    script.load()
    device_frida.resume(pid)
    #running monkeyscript
    os.system(android_home+' monkeyscript.py')
    time.sleep(10)
  except Exception as e:
    print("ERROR")
   

    
def on_message(message, data):
    print("frida")

    if 'payload' in message:
        payload = message['payload']  
        if 'Url' in payload:
            print("inFrida")
            data=[payload['packageName'],package,payload['method'],payload['Header'],payload['Url'],payload['userAgent']]
            file,writer=file_open1() 
            add_rows(writer,data)
            file.close()
device=None
writer=None
file=None
package=None
f_package=None

if __name__ == '__main__':

    file,writer=file_open() 
    device, client = connect()     
    uninstall_package(device)
    # open up camera app
    apks=read_files() 
    for apk in apks:
      if len(apk)>0:
       x=install_package(apk)
       package=apk
       if(x):
        frida_instument()
        uninstall_package(device)
        try:
         os.replace(path+"/"+apk,path1+"/"+apk)       
        except Exception as e:
             print("ERROR")
    file.close()



        
