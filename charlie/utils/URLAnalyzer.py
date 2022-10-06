
import os
import csv
import sys
url={}
leakage={}
packages={"1"}
javaScript={}

advid='9642a854-4e4e-4fe1-ab8c-606b3f2e10b'
advid1='39cb396f-fa39-41f8-b436-cabd6e44d151'
with open('user_agents.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row["packageName"] not in url:
             if "http://" in row["url"] and (advid in row["url"] or advid1 in row['url']):
              url[row["packageName"]]=[]
              url[row["packageName"]].append(row["url"])
              
            elif "http://" in row["url"] (advid in row["url"] or advid1 in row['url'])  :
              url[row["packageName"]].append(row["url"])              
      
  
       
        
        file = open('urlLeakge.csv', 'a')
        writer = csv.writer(file)  
        header = ["packageName","url"] 
        writer.writerow(header)        
        for key, value in url.items():
            data=[key,value]
            writer.writerow(data)
       