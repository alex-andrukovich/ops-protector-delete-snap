#!/usr/bin/env python3
# Usage: -s 10.0.0.20 -t 443 -u root -p Hhds1234! -a master -f g900_1_snap_data_flow -n g900_1 -i 10.0.0.117
import requests
import urllib.parse
import argparse
import json
from http.cookiejar import CookieJar
import sys
import os
import re
import subprocess
import time
import logging
import functools

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
file_handler = logging.FileHandler('ops-protector-delete-snap.log')  # Log to a file
stdout_handler = logging.StreamHandler()  # Log to stdout
# Create a formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stdout_handler.setFormatter(formatter)
# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stdout_handler)
def log_decorator(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        logger.info(f'Function {fn.__name__} called with args: {args} and kwargs: {kwargs}')
        return fn(*args, **kwargs)
    return wrapper


@log_decorator
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", dest="server",  help="Enter Hitachi Ops Center protector IP or hostname or FQDN")
    parser.add_argument("-t", "--tcpport", dest="tcpport", help="Enter Hitachi Ops Center protector TCP port")
    parser.add_argument("-u", "--username", dest="username", help="Enter Hitachi Ops Center protector username")
    parser.add_argument("-p", "--password", dest="password", help="Enter Hitachi Ops Center protector password")
    parser.add_argument("-a", "--authspace", dest="authspace", help="Enter Hitachi Ops Center protector auth space e.g. master")
    parser.add_argument("-f", "--flow", dest="flow", help="Enter Hitachi Ops Center protector data flow name")
    parser.add_argument("-n", "--node", dest="node", help="Enter Hitachi Ops Center protector node name")
    parser.add_argument("-i", "--ipofstorage", dest="ipofstorage", help="Enter ip of storage system to cleanup")
    arguments = parser.parse_args()
    if not arguments.server:
        parser.exit("[-] Enter Hitachi Ops Center protector IP or hostname or FQDN.")
    elif not arguments.tcpport:
        parser.exit("[-] Enter Hitachi Ops Center protector TCP port.")
    elif not arguments.username:
        parser.exit("[-] Enter Hitachi Ops Center protector username.")
    elif not arguments.password:
        parser.exit("[-] Enter Hitachi Ops Center protector password.")
    elif not arguments.authspace:
        parser.exit("[-] Enter Hitachi Ops Center protector auth space e.g. master.")
    elif not arguments.flow:
        parser.exit("[-] Enter Hitachi Ops Center protector data flow name.")
    elif not arguments.node:
        parser.exit("[-] Enter Hitachi Ops Center protector node name.")
    elif not arguments.ipofstorage:
        parser.exit("[-] Enter ip of storage system to cleanup.")
    return arguments

@log_decorator
def get_home_path():
    os_type = sys.platform
    if os_type == "win32":
        homedrive = os.environ.get('HOMEDRIVE')
        homepath = os.environ.get('HOMEPATH')
        full_homepath = homedrive + homepath + "\\"
    elif os_type == "linux":
        homepath = os.environ.get('HOME')
        full_homepath = homepath + "/"
    return full_homepath

@log_decorator
def is_valid_ip(ip):
    pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return bool(pattern.match(ip))

@log_decorator
def create_horcm_file(horcm_instance, path, storage_ip, udpport):
    horcm_file_full_path = path + "horcm" + horcm_instance + ".conf"
    with open(horcm_file_full_path, 'w') as horcm_file:
            horcm_file.write("HORCM_MON" + '\n')
            horcm_file.write("#ip_address" + '\t' + "service" + '\t' + "poll(10ms)" + '\t' + "timeout(10ms)" + '\n')
            horcm_file.write("localhost" + '\t' + udpport + '\t' + "1000" + '\t\t' + "3000" + '\n\n\n')
            horcm_file.write("HORCM_CMD" + '\n')
            horcm_file.write("#dev_name" + '\t' + "dev_name" + '\t' + "dev_name)" + '\t' + "dev_name" + '\n')
            if is_valid_ip(storage_ip):
                horcm_file.write("\\\\.\\IPCMD-" + storage_ip + "-31001" + '\n')
            else:
                horcm_file.write(storage_ip  + '\n')

@log_decorator
def shutdown_horcm_instance(horcm_instance, path):
    os_type = sys.platform
    horcm_file_full_path = path + "\\" + "horcm" + horcm_instance + ".conf"
    os.environ['HORCM_CONF'] = horcm_file_full_path
    os.environ['HORCMINST'] = horcm_instance
    os.environ['HORCM_EVERYCLI'] = "1"
    if os_type == "win32":
        subprocess.run(["horcmshutdown"])
    elif os_type == "linux":
        subprocess.run(["horcmshutdown.sh"])
    time.sleep(10)

@log_decorator
def start_horcm_instance(horcm_instance, path):
    os_type = sys.platform
    try:
        shutdown_horcm_instance(horcm_instance, path, os_type)
    except:
        logger.info("Could not shutdown HORCM instance, might be down already")
    horcm_file_full_path = path + "horcm" + horcm_instance + ".conf"
    os.environ['HORCM_CONF'] = horcm_file_full_path
    os.environ['HORCMINST'] = horcm_instance
    os.environ['HORCM_EVERYCLI'] = "1"
    if os_type == "win32":
        subprocess.run(["horcmstart"])
    elif os_type == "linux":
        subprocess.run(["horcmstart.sh"])
    time.sleep(10)


@log_decorator
def send_request_with_data_post(session, url, data):
    headers = {'Content-Type': 'application/json'}
    response = session.post(url, data=data, verify=False, headers=headers)
    logger.info(data)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_without_data_post(session, url):
    headers = {'Content-Type': 'application/json'}
    response = session.post(url, verify=False, headers=headers)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_with_data_put(session, url, data):
    headers = {'Content-Type': 'application/json'}
    response = session.put(url, data=data, verify=False, headers=headers)
    logger.info(data)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_without_data_get(session, url):
    response = session.get(url, verify=False)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_without_data_delete(session, url):
    response = session.delete(url, verify=False)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')


@log_decorator
def find_values(json_data, key_to_find):
    values = []
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if key == key_to_find:
                values.append(value)
            if isinstance(value, (dict, list)):
                values.extend(find_values(value, key_to_find))
    elif isinstance(json_data, list):
        for item in json_data:
            values.extend(find_values(item, key_to_find))
    return values

@log_decorator
def check_qs_still_exists_recursive(horcm_instance):
    time.sleep(60)
    os_type = sys.platform
    ldev_dict = {}
    ldev_dict_of_dict = {}
    array_ldevs_mapped = []
    ldevs_mapped = subprocess.check_output(
        ["raidcom", "get", "ldev", "-fx", "-ldev_list", "mapped", "-I" + horcm_instance])
    ldevs_mapped = ldevs_mapped.decode()
    if os_type == "win32":
        array_ldevs_mapped = ldevs_mapped.split("\r\n\r\n")
    elif os_type == "linux":
        array_ldevs_mapped = ldevs_mapped.split("\n\n")
    array_ldevs_mapped.pop()
    qs = False
    for ldev in array_ldevs_mapped:
        ldev_line = ldev.splitlines()
        for sub_ldev_line in ldev_line:
            if "QS" in sub_ldev_line and "VOL_ATTR" in sub_ldev_line:
                logger.info(sub_ldev_line)
                qs = True
    if qs:
        check_qs_still_exists_recursive(horcm_instance)
    else:
        return False



@log_decorator
def raidcom_login(horcm_instance, username, password):
    subprocess.run(["raidcom", "-login", username, password, "-I"+horcm_instance])

@log_decorator
def deactivate_dataflow(session, base_url, dataflow_name):
    deactivate_suffix = "/API/" + api_version + "/master/RulesManager/services/Rules/actions/deactivate/invoke"
    data_flows_suffix = "/API/" + api_version + "/master/DataFlowHandler/objects/DataFlows"
    data_flows = send_request_without_data_get(session, base_url + data_flows_suffix)
    json_data_flows = json.dumps(data_flows, indent=4)
    for item in data_flows['dataflow']:
        if str(item['data']['name']) == protector_server_flow:
            logger.info(str(item['data']['name']))
            logger.info(str(item['id']))
            ids = {}
            ids['ids'] = []
            ids['ids'].append(str(item['id']))
            ids_json = json.dumps(ids)
            # deactivate the flow
            deactivate_output = send_request_with_data_put(session, base_url + deactivate_suffix, ids_json)
    return None

@log_decorator
def activate_dataflow(session, base_url, dataflow_name):
    compile_suffix = "/API/" + api_version + "/master/RulesManager/services/Rules/actions/compile/invoke"
    distribute_suffix = "/API/" + api_version + "/master/RulesManager/services/Rules/actions/distribute/invoke"
    data_flows_suffix = "/API/" + api_version + "/master/DataFlowHandler/objects/DataFlows"
    data_flows = send_request_without_data_get(session, base_url + data_flows_suffix)
    json_data_flows = json.dumps(data_flows, indent=4)
    for item in data_flows['dataflow']:
        if str(item['data']['name']) == protector_server_flow:
            logger.info(str(item['data']['name']))
            logger.info(str(item['id']))
            ids = {}
            ids['ids'] = []
            ids['ids'].append(str(item['id']))
            ids_json = json.dumps(ids)
            # activate the flow
            compile_output = send_request_with_data_put(session, base_url + compile_suffix, ids_json)
            distribute_output = send_request_with_data_put(session, base_url + distribute_suffix, ids_json)
    return None


@log_decorator
def delete_all_snapshots_of_a_storage_system(session, base_url, protector_server_node, horcm_inst):
    recovery_points_suffix = "/API/" + api_version + "/master/RecoveryPointMetaDataAggregator/objects/RecoveryPoints"
    snapshots = send_request_without_data_get(session, base_url + recovery_points_suffix)
    for i, snap in enumerate(snapshots['recoveryPoint']):
        if protector_server_node in snap['storageNode']['id']:
            snapshot_id = snapshots['recoveryPoint'][i]['id']
            snapshot_id_url_fmt = urllib.parse.quote_plus(snapshot_id)
            node = snapshot_id.split("/")[0]
            node_url_fmt = urllib.parse.quote_plus(node)
            snap = snapshot_id.split("/")[1]
            snap_url_fmt = urllib.parse.quote_plus(snap)
            delete_snap_base_suffix = "/API/" + api_version + "/" + node_url_fmt + "/VirtualStoragePlatformHandler/objects/Snapshots/"
            get_snap_base_suffix = "/API/" + api_version + "/" + node_url_fmt + "/VirtualStoragePlatformHandler/objects/Snapshots/"
            get_snapshot_before_delete = send_request_without_data_get(session, base_url + get_snap_base_suffix + snapshot_id_url_fmt)
            logger.info(get_snapshot_before_delete)
            delete_snapshot_now = send_request_without_data_delete(session, base_url + delete_snap_base_suffix + snapshot_id_url_fmt)
    check_qs_still_exists_recursive(horcm_inst)
    return None



user_input = get_arguments()

protector_server = user_input.server
protector_server_tcp_port = user_input.tcpport
protector_server_username = user_input.username
protector_server_password = user_input.password
protector_server_authspace = user_input.authspace
protector_server_flow = user_input.flow
protector_server_node = user_input.node
storage_ip = user_input.ipofstorage
base_url = "https://" + protector_server + ":" + protector_server_tcp_port

login_data = {}
login_data['username'] = user_input.username
login_data['password'] = user_input.password
login_data['space'] = user_input.authspace
login_data_json = json.dumps(login_data)

api_version = "7.1"
nodes_suffix = "/API/" + api_version + "/master/NodeManager/objects/Nodes"
login_suffix = "/API/" + api_version + "/master/UIController/services/Users/actions/login/invoke"
logout_suffix = "/API/" + api_version + "/master/UIController/services/Users/actions/logout/invoke"

horcm_inst = "666"
horcm_udp = "44666"
horcm_username = "maintenance"
horcm_password = "raid-maintenance"
home_path = get_home_path()
create_horcm_file(horcm_inst, home_path, storage_ip, horcm_udp)
start_horcm_instance(horcm_inst, home_path)
raidcom_login(horcm_inst, horcm_username, horcm_password)


# Create a new CookieJar object
jar = CookieJar()
# Create a session
session = requests.session()
# Use the CookieJar as the session's cookie store
session.cookies = jar
# Now you can send requests through the session, and cookies will be stored in the jar
# response = session.get('https://example.com')
# The cookies received in the response are now stored in the jar

# login example:
try:
    login = send_request_with_data_post(session, base_url + login_suffix, login_data_json)
    logger.info(login)
except Exception as e:
    logger.info(e)

# list all nodes example:
# try:
#     nodes = send_request_without_data_get(session, base_url + nodes_suffix)
#     json_nodes = json.dumps(nodes, indent=4)
#     logger.info(json_nodes)
# except Exception as e:
#     logger.info(e)


deactivate_dataflow(session, base_url, protector_server_flow)
delete_all_snapshots_of_a_storage_system(session, base_url, protector_server_node, horcm_inst)
activate_dataflow(session, base_url, protector_server_flow)


# logout example:
try:
    logout = send_request_without_data_post(session, base_url + logout_suffix)
    logger.info(logout)
except Exception as e:
    logger.info(e)

shutdown_horcm_instance(horcm_inst, home_path)