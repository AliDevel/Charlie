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

# Charlie --- Android WebView Fingerprints

Charlie is an tool for collecting fingerprints in Android Webview. It relies on an dynamic instrumentation based on Frida. It currently supports monkey testing to increase coverage.

### Tool
You can find `charlie` in the `charlie` directory.
### Dependencies

Charlie requires the following dependencies:
- Python 3
- [Frida](https://frida.re) Dynamic Instrumentation 
- Python 3

Additionally, you need to have the Android SDK and 

### Instructions
Charlie is a python script and can be run via `python3 charlie.py` within the `charlie` directory. 

### Developers

Ignored for double blind submission
