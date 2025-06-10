# scp_core.py
import os
import paramiko
from scp import SCPClient
from tqdm import tqdm

def create_ssh_client(host, port, user, password):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=user, password=password)
    return ssh

def get_total_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total

def scp_upload(ssh_client, local_path, remote_path, recursive=False):
    total_size = get_total_size(local_path)
    progress = tqdm(total=total_size, unit='B', unit_scale=True)

    def progress_callback(filename, size, sent):
        progress.update(sent - progress.n)

    with SCPClient(ssh_client.get_transport(), progress=progress_callback) as scp:
        scp.put(local_path, remote_path, recursive=recursive)

    progress.close()
