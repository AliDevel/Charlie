"""
Copyright (c) 2023 Alimerdan Rahimov, Jyoti Prakash, Abhishek Tiwari, Christian Hammer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import csv
import logging
import os
import re
import subprocess
import sys
import time
from argparse import ArgumentParser, RawTextHelpFormatter
from platform import system
import frida
from ppadb.client import Client as AdbClient
from time import time

logger = logging.getLogger('Charlie')
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                    format='[%(levelname)-6s]  %(message)s')

FRIDA_LOG_FILE = 'frida.csv'


def is_unix():
    return system() in ['Linux', 'Darwin']

ev_js = """'use strict';

if (Java.available) {

    Java.perform(function() {

        var WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            this.loadUrl(url);
            const ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var packagename = context.getPackageName();
            send({
                packageName: packagename,
                method: "loadUrl",
                Url: url,
                Header: "",
                userAgent: this.getSettings().getUserAgentString()
            });
            console.log("WebView.loadUrl url:" + url);
        }

        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, header) {
            this.loadUrl(url, header);
            var keyset = url.keySet();
            var it = keyset.iterator();
            while (it.hasNext()) {
                var keystr = it.next().toString();
                var valuestr = url.get(keystr).toString();
				var s=keystr+valuestr;
                console.log("Header" + keystr + ":" + valuestr)
                send({
                    method: "loadUrlHeader",
                    Url: url,
                    Header:s,
                    userAgent: this.getSettings().getUserAgentString()
                });
            }
           
        }

        WebView.postUrl.overload('java.lang.String', '[B').implementation = function(url, data) {
            console.log("WebView.postUrl :" + url);
            send({
                method: "postUrl",
                Header: "",
                userAgent: this.getSettings().getUserAgentString()
            });
            this.postUrl(url, data);
        }

        WebView.loadDataWithBaseURL.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(url, p2, p3, p4, p5) {
            this.loadDataWithBaseURL(p1, p2, p3, p4, p5);
            send({
                method: "loadDataWithBaseURL",
                Header: "",
                Url: url,
                userAgent: this.getSettings().getUserAgentString()
            });
        };

        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(p0, p1, p2) {
            this.loadUrl(p0, p1, p2);
            console.log("loaddata" + p0 + p1 + p2);
        }

        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onLoadResource.overload('android.webkit.WebView', 'java.lang.String').implementation = function(p0, url) {
            console.log(p0 + url);
            const ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var packagename = context.getPackageName();
            send({
                packageName: packagename,
                method: "onLoadResource",
                Header: "",
                Url: url,
                userAgent: p0.getSettings().getUserAgentString()
            });
            this.onLoadResource(p0, url);

        }
    });
}
"""

def log_instrumentation(message, data):
    logger.info("Logging from frida")
    payload = message['payload']
    if payload is not None:
        if 'Url' in payload:
            data = [payload['packageName'], payload['method'],
                    payload['Header'], payload['Url'], payload['userAgent']]
            with open(FRIDA_LOG_FILE, 'a') as f:
                writer = csv.writer(f)
                writer.writerow(data)


class InstrumentEnv:
    def __init__(self, hostname: str, port: str):
        """
        Initializes the Instrumentation environment
        :param hostname: ADB Hostname (default: 127.0.0.1)
        :param port: ADB Port (default: 5037)
        """
        self.client = None
        self.device = None
        self.monkey_runner = None
        self.hostname = hostname
        self.port = port
        self.android_sdk_root = os.getenv('ANDROID_SDK_ROOT')
        self.__connect__()

    def __install_package__(self, apk: str) -> None:
        """
        Installs the apk file in the device (or emulator)
        :param apk:
        :return:
        """
        try:
            self.device.install(apk)
            logger.info(f'Installed package {apk}')
        except Exception as e:
            logger.error(f"Failed to install {apk}, error={e}")

    def __set_up_monkey_runner__(self):
        android_bin = os.path.join(self.android_sdk_root, 'tools', 'bin')
        logger.debug(android_bin)
        if system() == 'Java':
            logger.error("Unsupported system Java. Exiting.")
            exit(10)
        self.monkey_runner = os.path.join(
            android_bin, 'monkeyrunner' if is_unix() else 'monkeyrunner.bat')
        logger.info(self.monkey_runner)

    def __connect__(self) -> None:
        # Default is "127.0.0.1" and 5037
        self.client = AdbClient(host=self.hostname, port=self.port)
        logger.info(f'Connected to ADB Client {self.hostname}:{self.port}')
        devices = self.client.devices()
        if len(devices) == 0:
            logger.error("No devices found to connect. Exiting.")
            quit(9)
        self.device = devices[0]
        print(f'Connected to {self.device}')

    def __search_package_in_avd__(self):
        command = self.device.shell('pm list packages -3 | cut -f 2 -d :')
        # packages = re.split(os.linesep, command)
        packages = re.split('[:\r\n]', command)
        for package in packages:
            print(package + "\n")
        if not packages:
            logger.error("Could not find any packages in the device")
            return ""
        else:
            return packages

    def __clean__(self):
        """
        Cleans the device before installation
        :return:
        """
        packages = self.__search_package_in_avd__()
        for package in packages:
            self.device.uninstall(package)
            print(package + " uninstalled")

    def __run_frida__(self, apk):
        self.__set_up_monkey_runner__()
        logger.info(f"Running {apk} with Frida")
        try:
            device_frida = frida.get_usb_device()
            f_package = self.__search_package_in_avd__()[0]
            pid = device_frida.spawn([f_package])
            session = device_frida.attach(pid)
            # script = session.create_script(open("ev.js").read())
            script = session.create_script(ev_js)
            script.on("message", log_instrumentation)
            script.load()
            device_frida.resume(pid)
            # Running monkey script
            os.system(self.monkey_runner + ' monkeyscript.py')
            subprocess.run([self.monkey_runner, 'monkeyscript.py'])
            time.sleep(10)
        except Exception as e:
            logger.error(e)

    def run(self, apk_file: str) -> None:
        self.__clean__()
        self.__install_package__(apk=apk_file)
        start = time.time_ns()
        self.__run_frida__(apk=apk_file)
        logger.info(f"Analyzed {apk_file} in {(time.time_ns()-start)/1000} milliseconds")
        self.__clean__()


def main() -> None:
    parser = ArgumentParser('charlie.py', formatter_class=RawTextHelpFormatter)
    parser.add_argument('-l', dest='adb_host', type=str,
                        help='adb hostname (default=127.0.0.1)', default='127.0.0.1')
    parser.add_argument('-p', dest='adb_port', type=str,
                        help='adb port (default=5037)', default=5037)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', dest='directory', type=str,
                       help='analyze all apk files in the directory')
    group.add_argument('-a', dest='apk_file', type=str, help='analyze apk')
    args = parser.parse_args()

    if args.directory is not None:
        logger.info(f'Using Android SDK root={android_sdk_root}')
        for apk_file in os.listdir(args.directory):
            if apk_file.endswith(".apk"):
                instrument = InstrumentEnv(hostname=args.adb_host, port=args.adb_port)
                instrument.run(apk_file=os.path.abspath(os.path.join(args.directory, apk_file)))
        logger.info("Analysis completed")
    elif args.apk_file:
        logger.info(f'Using Android SDK root={android_sdk_root}')
        instrument = InstrumentEnv(hostname=args.adb_host, port=args.adb_port)
        instrument.run(apk_file=os.path.abspath(args.apk_file))
        logger.info("Analysis completed")
    else:
        parser.print_help(sys.stderr)
        exit(9)


if __name__ == '__main__':
    android_sdk_root = os.getenv('ANDROID_SDK_ROOT')
    if android_sdk_root is None:
        print(f"ANDROID_SDK_ROOT is not set")
        exit(9)
    main()
