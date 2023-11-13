from flask import request


def get_ip_address():
    return '118.93.181.112' if request.remote_addr == '127.0.0.1' else request.access_route[-1] # todo: make 118.93.181.112 into a .env variable

