from Crypto.Hash import SHA256

import os

def get_hash(payload):
    h = SHA256.new()
    h.update(payload)
    return h.hexdigest()

def get_file_info(path):
    size = os.path.getsize(path)
    file = open(path, "r")
    fileHash = get_hash(file.read().encode("utf-8"))
    return fileHash, size

def check_dir(root, target):
    root = os.path.abspath(root)
    target = os.path.abspath(target)
    return os.path.commonpath([root]) == os.path.commonpath([root, target])