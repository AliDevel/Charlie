<!-- Prerequisites for running the Automatic Hybrid Application Test Tool:
1.You need to download the apps. 
 We downloaded our apps from the Androzoo dataset[https://androzoo.uni.lu/].
2.Frida server must be installed on the device. 
 Please refer to the official frida website to install on your device[https://frida.re/docs/android/].
3.Change the localization of the applications folder in Automatedtesting.py.
  The $path variable contains information about the location of the applications to be tested. After testing applications, they are 
  are moved to the folder $path1. 

Once the prerequisites are met, the dynamic toolkit is ready to run. 

$ py automatedtesting.py 


It creates a user_agents.csv file that contains package names, urls, user headers, and user agent strings.

The DatasetAnalyzer.py script analyzes the resulting dataset, grouping it for unencrypted traffic, user agent strings 
by their similarity, as well as by the number of unique packets from which we obtained the data.

$ py DatasetAnalyzer.py -->

# Charlie: Android WebView Fingerprints

Charlie is an tool for collecting fingerprints in Android Webview. It relies on an dynamic instrumentation based on Frida. It currently supports monkey testing to increase coverage.

### Tool
You can find `charlie` in the `charlie` directory.
### Dependencies

Charlie requires the following dependencies:
- Python 3 with pip
- [Frida](https://frida.re) Dynamic Instrumentation
- Android SDK - You need to have the Android SDK and initialize the `ANDROID_SDK_ROOT` environment variable. Install it with [Android Studio](https://developer.android.com/studio) or install it from [command line tools](https://developer.android.com/studio/command-line).

### Instructions
Charlie is a python script and can be run via `python3 charlie.py` within the `charlie` directory. As of now, it is necessary to run Charlie on an emulated device. PLEASE DON'T RUN CHARLIE ON A PERSONAL DEVICE, YOU MIGHT LOOSE INSTALLED APPS.

First, you need to setup Frida server. Follow these instructions (https://frida.re/docs/android/) to setup Frida. 

Next, you can run charlie via the python script `python3 charlie.py`. Please ensure that you run `charlie` from `charlie` directory. You need to specify the apk file `[-a]` or the directory containing a bunch of apk files `[-d]`. By default, it uses <tt>127.0.0.1</tt> and <tt>5037</tt> as adb client and port. 

Charlie usage looks like

```shell
usage: charlie.py [-h] [-d DIR] [-a APK_FILE] [-l ADB_HOST] [-p ADB_PORT]

options:
  -h, --help   show this help message and exit
  -d DIR       analyze all apk files in the directory
  -a APK_FILE  analyze apk
  -l ADB_HOST  adb hostname (default=127.0.0.1)
  -p ADB_PORT  adb port (default=5037)
 ```
 
### Developers

- Alimerdan Rahimov, Developer (alimerdan.rahimov@gmail.com)
- Jyoti Prakash & Abhishek Tiwari, Mentors (jpksh90@gmail.com, mig40000@gmail.com)



