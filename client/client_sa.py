# Siavash 2025/01/05: Created the initial version of the client file. basically copied from the server file with minor changes.

import logging
import time
import socket
import platform
import subprocess
import os
import pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import getpass
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

env = "prod"  # Siavash 2024/09/03: Ideally, this should have been a constant, but Python doesn't have built-in support for true constants. Since this is not a team environment, we should be fine.
# Siavash 2024/09/03: The intent for using an env variable is to allow adjusting the logging feature depending on the environment. For example, we may not want to log many details in production, but during development, more logging information is needed.


def initLogger():
    if env != "prod":
        print("Initializing the logger")
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timeStamp = time.strftime("%Y%m%d_%H%M_%S")
    # Siavash 2024/08/31: Here I create a time stamp which indicates when the server started execution; I intend to use this to name the log files. I modified the example provided here to generate a time stamp: https://stackoverflow.com/questions/10607688/how-to-create-a-file-name-with-the-current-date-time-in-python
    logfile = os.path.join(log_dir, f"client_{timeStamp}.log")
    if env != "prod":
        print(f"setting logger to: {logfile}")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(logfile)],
        # filename=logfile Siavash 2024/08/31 replaced this line with the above handlers section, to print to the terminal in addition to the log file. The setting was suggested by: https://stackoverflow.com/a/46098711
    )

    logger = logging.getLogger()
    if env == "dev":
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler())
    elif env == "prod":
        logger.setLevel(logging.INFO)

    logging.debug(f"logger set to: {logfile}")


def ping_ip(ip):
    logging.info(f"Attempting to ping {ip}...")
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]

    try:
        output = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        return output.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def connect(ip, port):
    logging.debug(f"Attempting to connect to {ip}:{port}...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5)
        client_socket.connect((ip, int(port)))
        logging.info("Successfully connected!")
        return client_socket
    except socket.error as e:
        msg = f"Failed to connect: {e}"
        logging.exception(msg)
        printMsgInProd(msg)
        return None


def init():
    if env != "prod":
        print("Initializing the client.")
    initLogger()


def printMsgInProd(msg):
    if env == "prod":
        print(msg)


def valid_ip_format(ip_input):
    try:
        logging.debug(f"Validating format of the entered IP: {ip_input}")
        if not ip_input:
            msg = "Invalid IP address. Input cannot be empty."
            logging.error(msg)
            printMsgInProd(msg)
            return False

        parts = ip_input.split(".")
        if len(parts) != 4:
            msg = "Invalid IPv4 address."
            logging.error(msg)
            printMsgInProd(msg)
            return False

        for part in parts:
            try:
                n = int(part)
                if not (0 <= n <= 255):
                    msg = f"Invalid IP address. Each octet must be between 0 and 255. Invalid octet: {part}"
                    logging.error(msg)
                    printMsgInProd(msg)
                    return False
            except ValueError:
                msg = f"Invalid IP address. Each octet must be a valid integer. Invalid octet: {part}"
                logging.error(msg)
                printMsgInProd(msg)
                return False

        logging.debug("Entered IP considered valid.")
        return True
    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        return False


def valid_port(port_input):
    try:
        port_number = int(port_input)
        if 0 <= port_number <= 65535:
            logging.debug("Entered port considered valid.")
            return True
        else:
            msg = "Invalid port number. Port number must be between 0 and 65535."
            logging.error(msg)
            printMsgInProd(msg)
            return False
    except ValueError:
        msg = "Invalid port number."
        logging.error(msg)
        printMsgInProd(msg)
        return False


def valid_name(name, accounts: list):
    logging.info(f"Validating entered name: {name}")
    name = name.strip()
    if not name[0].isalpha():
        logging.info("Invalid name. Must start with an alphabet.")
        return False
    if not name.isalnum():
        logging.info("Invalid name. Must contain only letters and numbers.")
        return False
    if len(name) > 9:
        logging.info("Invalid name. Must  be less than 8 characters long.")
        return False
    # if accounts:
    #     if name in accounts:
    #         logging.info("Invalid name. Must  be unique.")
    #         return False

    return True


def getNewID(objects) -> int:
    if not objects:
        return 1

    existing_ids = set(obj["id"] for obj in objects if "id" in obj)

    if not existing_ids:
        return 1

    max_id = max(existing_ids)

    for new_id in range(1, max_id + 2):
        if new_id not in existing_ids:
            return new_id

    return 0


def getValidRecipients(username):
    recipients = []
    for filename in os.listdir("keys"):
        if filename.endswith("_pb_key.pem"):
            string_part = filename[:-11]
            if string_part != "server" and string_part != username:
                recipients.append(string_part)
    return recipients


def acc_shared_changed(list1, list2):
    return set(list1) != set(list2)


session_key: bytes
session_socket: socket.socket


def getPublicKey(username):
    pb_key_file = os.path.join(
        "keys",
        username + "_pb_key.pem",
    )
    if os.path.isfile(pb_key_file):
        with open(pb_key_file, "rb") as f:
            pb_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend(),
            )
        return pb_key


def start():
    global session_socket
    global session_key
    try:
        welcome_msg = "Welcome to the cn-test app!"
        logging.info(welcome_msg)
        printMsgInProd(
            welcome_msg
        )  # Siavash 2024/09/03: this not an important entry hence the "debug" level; I'm just trying to record when the program started.

        while True:
            if env == "dev":
                server_ip = "127.0.1.1"
            elif env == "prod":
                server_ip = input("Enter the server IP address: ")

            if valid_ip_format(server_ip):
                # if ping_ip(server_ip): #Siavash 9/22/204 commented out - ping is not helpful for CS-610 since we cannot ping STU.
                if env == "dev":
                    server_port = 5099
                elif env == "prod":
                    server_port = input("Enter the server port: ")
                if valid_port:
                    client_socket = connect(server_ip, server_port)
                    if client_socket:
                        session_socket = client_socket
                        break
                    else:
                        print("Please try again. Or press Ctrl + C to exit.")

        username = input("Enter your username (case sensitive!): ")
        client_socket.send(username.encode())
        res = client_socket.recv(1024).decode()
        logging.info(res)
        printMsgInProd(res)

    except KeyboardInterrupt:
        logging.info(
            "\nProgram interrupted (KeyboardInterrupt). Client is shutting down."
        )
    finally:
        session_key = None
        session_socket = None
        print("Bye!")


def main():
    try:
        clear_console()
        init()
        start()
    except Exception as e:
        logging.exception(
            f"An error occurred: {e}\n Please contact Siavash Ashkiani at ashkiasx@dukes.jmu.com for assistance."
        )
    else:
        ...
    finally:
        ...


def clear_console():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


main()
