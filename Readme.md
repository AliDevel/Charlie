Prerequisites for running the Automatic Hybrid Application Test Tool:
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

$ py DatasetAnalyzer.py
