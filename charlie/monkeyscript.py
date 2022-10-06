# Imports the monkeyrunner modules used by this program
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
import random
# Connects to the current device, returning a MonkeyDevice object
device = MonkeyRunner.waitForConnection()

# Installs the Android package. Notice that this method returns a boolean, so you can test
# to see if the installation worked.
#device.installPackage('C:\\Users\\alime\\AndroidStudioProjects\\instagram.apk')

# sets a variable with the package's internal name
#package = 'xyz.quube.mobile'

# sets a variable with the name of an Activity in the package
#activity = 'com.instagram.android.activity.MainTabActivity'

# sets the name of the component to start
#runComponent = package + '/' + activity

# Runs the component
#device.startActivity(component=runComponent)

# Presses the Menu button
#device.press('KEYCODE_MENU', MonkeyDevice.DOWN_AND_UP)
screenW = float(device.getProperty("display.width"))
screenH = float(device.getProperty("display.height"))
print screenW 
print screenH
print "start monkey test"

for i in range(1, 50):
     a=random.randint(10,screenW)
     b=random.randint(100,screenH)
     print a,b
     device.touch(a, b, 'DOWN_AND_UP')
     MonkeyRunner.sleep(1)
   
print "end monkey test"
