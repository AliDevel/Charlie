import subprocess
import time
import argparse

from ppadb.client import Client as AdbClient
from typing import AnyStr, List

import re
import os
import csv
import frida
import logging
from pathlib import Path
from platform import system

# Applications folder
path = 'F:/automatization/app'
# Tested Applications folder
path1 = 'F:/automatization/app3'
# Path to monkeyrunner
# point it to monkey runner

# Connecting for a device

logger = logging.getLogger('CharlieInstrument')

FRIDA_LOG_FILE = 'frida.log'


def is_unix():
    return system() in ['Linux', 'Darwin']


# def file_open1():
#     file = open('eval1.csv', 'a')
#     writer = csv.writer(file)
#     return file, writer
#
#
# def add_rows(writer, data):
#     writer.writerow(data)


def log_instrumentation(message, data):
    logger.info("Logging from frida")
    payload = message['payload']
    if payload is not None:
        if 'Url' in payload:
            # print("inFrida")
            # data = [payload['packageName'], package, payload['method'],
            #         payload['Header'], payload['Url'], payload['userAgent']]

            # @Alimerdan: Do we need the "package" here?
            data = [payload['packageName'], payload['method'],
                    payload['Header'], payload['Url'], payload['userAgent']]
            with open(FRIDA_LOG_FILE) as f:
                writer = csv.writer(f)
                writer.writerow(data)
            # file, writer = file_open1()
            # file.close()


class InstrumentEnv:
    def __init__(self, apk: str):
        self.client = None
        self.device = None
        self.apk = apk
        self.monkey_runner = None
        self.connect()

    def install_package(self):
        try:
            self.device.install(self.apk)
            logger.info(f'Installed package {self.apk}')
            # return True
        except Exception as e:
            logger.error(f"Failed to install {self.apk}")
            # print("Error" + str(e))
            # try:
            #     os.remove(path + "/" + self.apk)
            # except Exception as e:
            #     print("Error" + str(e))
            # return False

    def set_up_monkey_runner(self):
        android_bin = os.path.join(os.getenv('ANDROID_SDK_ROOT'), 'tools', 'bin')

        if system() == 'JAVA':
            logger.error("Unsupported system java. Existing.")
            exit(10)
        self.monkey_runner = os.path.join(android_bin, 'monkeyrunner' if is_unix() else 'monkeyrunner.bat')

    def connect(self) -> None:
        # Default is "127.0.0.1" and 5037
        self.client = AdbClient(host="127.0.0.1", port=5037)
        logger.info(f'Connected to ADB Client {self.client}')
        devices = self.client.devices()
        if len(self.devices) == 0:
            logger.error("[connect] No devices found. Quiting.")
            quit(9)
        self.device = devices[0]
        print(f'Connected to {self.device}')
        # return device, client

    def search_package_in_avd(self):
        command = self.device.shell('pm list packages -3 ' + '|cut -f 2 -d ' + ':')
        packages = re.split(os.linesep, command)
        for package in packages:
            print(package + "\n")
        if not packages:
            return ""
        else:
            return packages

    def clean(self):
        packages = self.search_package_in_avd()
        for package in packages:
            self.device.uninstall(package)
            print(package + " uninstalled")

    def run_frida(self):
        self.set_up_monkey_runner()
        logger.info(f"Running {self.apk} with Frida")
        try:
            device_frida = frida.get_usb_device()
            f_package = self.search_package_in_avd()[0]
            pid = device_frida.spawn([f_package])
            session = device_frida.attach(pid)
            script = session.create_script(open("ev.js").read())
            script.on("message", log_instrumentation)
            script.load()
            device_frida.resume(pid)
            # running monkeyscript
            # os.system(self.monkey_runner + ' monkeyscript.py')
            subprocess.run([self.monkey_runner, 'monkeyscript.py'])
            time.sleep(10)
        except Exception as e:
            logger.error(e)

    def run(self):
        self.clean()
        self.install_package()
        self.run_frida()
        self.clean()


def read_files():
    files = os.listdir(path)
    return files


def file_open():
    header = ["packageName", "package", "header", "method", "url", "useragent"]
    file = open('eval1.csv', 'a')
    writer = csv.writer(file)

    writer.writerow(header)
    return file, writer


# device = None
# writer = None
# file = None
# package = None
# f_package = None

def analyze_apks(directory: str) -> None:
    for apk in os.listdir(directory):
        analyze_apk(apk)


def analyze_apk(apk: str) -> None:
    if apk.endswith(".apk"):
        instrument = InstrumentEnv(apk)
        instrument.run()


def main() -> None:
    # file, writer = file_open()
    # device, client = InstrumentEnv.get_environment()
    # uninstall_package(device)
    # apks = read_files()
    parser = argparse.ArgumentParser('description: charlie --- Android WebView Instrumentation')
    parser.add_argument('-d', dest='dir', type=str, help='analyze APKs in the directory')
    parser.add_argument('-a', dest='apk', type=str, help='analyze apk')
    args = parser.parse_args()

    if args.dir:
        analyze_apks(directory=args.dir)

    if args.apk:
        analyze_apk(apk=args.apk)

    logger.info("Analysis completed")

    # if args.dir is None
    #
    # for apk in apks:
    #     if len(apk) > 0:
    #         x = install_package(apk)
    #         package = apk
    #         if (x):
    #             frida_instrument()
    #             uninstall_package(device)
    #             try:
    #                 os.replace(path + "/" + apk, path1 + "/" + apk)
    #             except OSError as e:
    #                 logger.error(f"{e.errno}::{e.strerror}")
    #
    # file.close()


if __name__ == '__main__':

    if os.getenv('ANDROID_SDK_ROOT') is None:
        print(f"ANDROID_SDK_ROOT is not set")
        exit(9)

    main()
