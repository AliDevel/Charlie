import pathlib
import subprocess
import sys
import time
import argparse
import configparser

from ppadb.client import Client as AdbClient
from typing import AnyStr, List

import re
import os
import csv
import frida
import logging
from pathlib import Path
from platform import system

logger = logging.getLogger('Charlie')
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='[%(levelname)-6s]  %(message)s')

FRIDA_LOG_FILE = 'frida.csv'


def is_unix():
    return system() in ['Linux', 'Darwin']


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
        # We need once establish a connection
        if self.device is None:
            self.connect()

    def install_package(self, apk: str) -> None:
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

    def set_up_monkey_runner(self):
        android_bin = os.path.join(self.android_sdk_root, 'tools', 'bin')
        logger.debug(android_bin)
        if system() == 'Java':
            logger.error("Unsupported system Java. Exiting.")
            exit(10)
        self.monkey_runner = os.path.join(android_bin, 'monkeyrunner' if is_unix() else 'monkeyrunner.bat')
        logger.info(self.monkey_runner)

    def connect(self) -> None:
        # Default is "127.0.0.1" and 5037
        self.client = AdbClient(host=self.hostname, port=self.port)
        logger.info(f'Connected to ADB Client {self.hostname}:{self.port}')
        devices = self.client.devices()
        if len(devices) == 0:
            logger.error("No devices found to connect. Exiting.")
            quit(9)
        self.device = devices[0]
        print(f'Connected to {self.device}')

    def search_package_in_avd(self):
        command = self.device.shell('pm list packages -3 ' + '|cut -f 2 -d :')
        # packages = re.split(os.linesep, command)
        packages = re.split('[:\r\n]', command)
        for package in packages:
            print(package + "\n")
        if not packages:
            logger.error("Could not find any packages in the device")
            return ""
        else:
            return packages

    def clean(self):
        """
        Cleans the device before installation
        :return:
        """
        packages = self.search_package_in_avd()
        for package in packages:
            self.device.uninstall(package)
            print(package + " uninstalled")

    def run_frida(self, apk):
        self.set_up_monkey_runner()
        logger.info(f"Running {apk} with Frida")
        try:
            device_frida = frida.get_usb_device()
            f_package = self.search_package_in_avd()[0]
            pid = device_frida.spawn([f_package])
            session = device_frida.attach(pid)
            script = session.create_script(open("ev.js").read())
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
        self.clean()
        self.install_package(apk=apk_file)
        self.run_frida(apk=apk_file)
        self.clean()


def main() -> None:
    parser = argparse.ArgumentParser('charlie.py')
    parser.add_argument('-d', dest='dir', type=str, help='analyze all apk files in the directory')
    parser.add_argument('-a', dest='apk_file', type=str, help='analyze apk')
    parser.add_argument('-l', dest='adb_host', type=str, help='adb hostname (default=127.0.0.1)', default='127.0.0.1')
    parser.add_argument('-p', dest='adb_port', type=str, help='adb port (default=5037)', default=5037)
    args = parser.parse_args()

    if args.dir is not None:
        logger.info(f'Using Android SDK root={android_sdk_root}')
        for apk_file in os.listdir(args.dir):
            if apk_file.endswith(".apk"):
                instrument = InstrumentEnv(hostname=args.adb_host, port=args.adb_port)
                instrument.run(apk_file=os.path.abspath(os.path.join(args.dir, apk_file)))
        logger.info("Analysis completed")
    elif args.apk_file:
        logger.info(f'Using Android SDK root={android_sdk_root}')
        instrument = InstrumentEnv(hostname=args.adb_host, port=args.adb_port)
        instrument.run(apk_file=os.path.abspath(args.apk_file))
        logger.info("Analysis completed")
    else:
        parser.print_help(sys.stderr)
        print("\nYou must specify either directory [-d] or apk [-a] path")



if __name__ == '__main__':
    android_sdk_root = os.getenv('ANDROID_SDK_ROOT')
    if android_sdk_root is None:
        print(f"ANDROID_SDK_ROOT is not set")
        exit(9)
    main()
