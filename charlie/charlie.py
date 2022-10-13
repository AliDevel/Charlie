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

logger = logging.getLogger('Charlie')
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                    format='[%(levelname)-6s]  %(message)s')

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
        self.__connect__()
        # # We need once establish a connection
        # if self.device is None:
        #     self.connect()

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
        self.__clean__()
        self.__install_package__(apk=apk_file)
        self.__run_frida__(apk=apk_file)
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
