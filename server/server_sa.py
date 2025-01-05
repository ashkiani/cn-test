# Siavash 2024/08/31: Created the initial version of this file. At this point I only included/experimented with logging library by following this YouTube Tutorial: https://www.youtube.com/watch?v=urrfJgHwIJA
# Siavash 2024/08/31: Added a custom filename for log files. Every time we start the server, we'll get a new log file that is time stamped.
# Siavash 2024/08/31: Added socket initialization for the server
# Siavash 2024/09/03: Added a logs folder
# Siavash 2024/09/09: Added netifaces to include IP addresses in addition to the loopback 127 address.

import logging
import time
import socket
import os
import pickle
import netifaces
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

env = "dev"  # Siavash 2024/09/03: Ideally, this should have been a constant, but Python doesn't have built-in support for true constants. Since this is not a team environment, we should be fine.
# Siavash 2024/09/03: The intent for using an env variable is to allow adjusting the logging feature depending on the environment. For example, we may not want to log many details in production, but during development, more logging information is needed.


def initLogger():
    if env != "prod":
        print("Initializing the logger")
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timeStamp = time.strftime("%Y%m%d_%H%M_%S")
    # Siavash 2024/08/31: Here I create a time stamp which indicates when the server started execution; I intend to use this to name the log files. I modified the example provided here to generate a time stamp: https://stackoverflow.com/questions/10607688/how-to-create-a-file-name-with-the-current-date-time-in-python
    logfile = os.path.join(log_dir, f"server_{timeStamp}.log")
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


def intiSocket() -> socket.socket:
    # Siavash 2024/08/31: I'm asking the OS to choose a port as I'm not sure what port I can use without the possibility of overstepping on other applications running on the machine. I found this discussion on StackOverflow that suggested to allow OS to pick the port and then print the information and share it with the client:  https://stackoverflow.com/a/32728740
    if env != "prod":
        logging.info("Initializing the socket.")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if env == "dev":
        port = 5099
    elif env == "prod":
        port = 0
    server.bind(("0.0.0.0", port))
    server.listen(5)
    _, port = server.getsockname()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    if ip_address.startswith("127."):
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr["addr"]
                    if ip != "127.0.0.1":
                        ip_address += ", " + ip

    separatorLen = 110
    server_info = f"""
    {'=' * separatorLen}
    SERVER INFORMATION
    {'=' * separatorLen}
    Server is listening on:
    IP Address: {ip_address}
    Port: {port}
    """
    info_message = f"""
    IMPORTANT: Write down the IP address(es) and the port.

    Note: 
    - If this server is behind a router, you may need to use your public IP address and set up port forwarding.
    - If your network doesn't allow public access, you will need to set up a VPN.
    {'=' * separatorLen}
    """

    if env == "dev":
        logging.info(server_info + info_message)
    elif env == "prod":
        logging.info(server_info)
        print(server_info + info_message)

    return server


server_pr_key = None


def init() -> socket.socket:
    if env != "prod":
        print("Initializing the server.")
    initLogger()
    return intiSocket()

def handle_client(client_socket):
    username = ""
    try:
        # userVerified = False
        # Siavash: first ID the client. If it's a valid username, then verify if by checking their public key.
        username = client_socket.recv(1024).decode()
        logging.info(f"Received username: {username}")
        res = f"Hello {username}! This is the server. Your message was received!"
        client_socket.send(res.encode())
        # profile_file_path = getProfileFilePath(username)
        # if os.path.isfile(profile_file_path):
        #     loaded_public_key = getProfilePbKey(username)
        #     if loaded_public_key:
        #         if not username in online_users:
        #             code: str = req_sig_verification(client_socket, loaded_public_key)
        #             signature = client_socket.recv(2048)
        #             if verify_signature(loaded_public_key, code.encode(), signature):
        #                 logging.info("Signature is valid.")
        #                 # this needs to be delayed since we're now using encrypted profiles and we need to ask user to decrypt it.
        #                 # Siavash: Now let's go ahead and load the profile
        #                 # with open(profile_file_path, "rb") as file:
        #                 #     profile = pickle.load(file)
        #                 #     online_users.append(username)
        #                 userVerified = True
        #             else:
        #                 logging.warning("Signature is invalid.")
        #                 client_socket.send(b"Unauthorized!")
        #         else:
        #             logging.error("This user is already logged in!")
        #             client_socket.send(
        #                 rsa_encrypt(
        #                     loaded_public_key, b"This user is already logged in!"
        #                 )
        #             )
        #             username = ""  # Siavash: I'm doing this so we don't mistakenly remove the already logged in user later in the code.
        #     else:
        #         logging.error(f"Failed to load public key for {username}.")
        #         client_socket.send(b"Unauthorized!")
        # else:
        #     client_socket.send(b"Unauthorized!")

        # if userVerified:
        #     logging.info(f"Telling {username} that server is ready.")
        #     client_socket.send(rsa_encrypt(loaded_public_key, b"Ready!"))
        #     if handle_sig_req(client_socket, logging, server_pr_key):
        #         key = handle_session_key_req(client_socket, logging, loaded_public_key)
        #         if key:
        #             handle_profile_request(key, client_socket, profile_file_path)
        #             # Siavash: From this point, we'll be working with encrypted communications
        #             while True:
        #                 data = recv_sec(key, client_socket, 1024)
        #                 logging.info(f"Received Main option: {data}")
        #                 option = int(data)
        #                 if option == 1:
        #                     while True:
        #                         # Siavash 11/10/2024: instead of sending a static text, we now send the shared files in every iteration since it might get updated by other users while we're in this loop.
        #                         # send_sec("Accounts Mode.".encode(), key, client_socket)
        #                         send_accounts_shared_with_user(
        #                             key, client_socket, username
        #                         )
        #                         data = recv_sec(key, client_socket, 1024)
        #                         logging.info(f"Received account option: {data}")
        #                         option = int(data)
        #                         if option == 1:
        #                             handle_newAcc(key, client_socket, username)
        #                         elif option == 2:
        #                             handle_delAcc(key, client_socket, username)
        #                         elif option == 3:
        #                             handle_viewAcc(key, client_socket, username)
        #                         elif option == 5:
        #                             handle_shareAcc(key, client_socket, username)
        #                         elif option == 0:
        #                             logging.info("Exiting from Accounts options")
        #                             break
        #                 elif option == 0:
        #                     logging.info("Client exited.")
        #                     break
        #                 else:
        #                     logging.info("This option is not recognized by the server!")
        #                     send_sec(
        #                         b"This option is not recognized by the server!",
        #                         key,
        #                         client_socket,
        #                     )

    except Exception as e:
        logging.exception(f"Error handling client: {e}")
    finally:
        logging.info("Closing client's socket.")
        # if online_users:
        #     if username in online_users:
        #         online_users.remove(username)
        # client_socket.close()


def start(server: socket.socket):
    logging.info("Starting the server.")

    try:
        while True:
            client_socket, addr = server.accept()
            logging.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket,)
            )
            client_thread.start()
    except KeyboardInterrupt:
        logging.info(
            "\nProgram interrupted (KeyboardInterrupt). Server is shutting down."
        )
    finally:
        server.close()
        logging.info("Socket closed.")


def main():
    try:
        # print("env: ",env)
        server: socket.socket = init()
        start(server)
    except Exception as e:
        logging.exception(
            f"An error occurred: {e}\n Please contact Siavash Ashkiani at ashkiasx@dukes.jmu.com for assistance."
        )
    finally:
        ...


main()
