# developed by Gabi Zapodeanu, TSA, GSS, Cisco Systems

# !/usr/bin/env python3

# !/usr/bin/env python3

import requests
import json
import time
import requests.packages.urllib3
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth  # for Basic Auth

from ERNA_init import SPARK_AUTH

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # Disable insecure https warnings

# The following declarations need to be updated based on your lab environment

PI_URL = 'https://172.16.11.25'
PI_USER = 'python'
PI_PASSW = 'Clive.17'
PI_AUTH = HTTPBasicAuth(PI_USER, PI_PASSW)

EM_URL = 'https://172.16.11.30/api/v1'
EM_USER = 'python'
EM_PASSW = 'Clive.17'

CMX_URL = 'https://172.16.11.27/'
CMX_USER = 'python'
CMX_PASSW = 'Clive!17'
CMX_AUTH = HTTPBasicAuth(CMX_USER, CMX_PASSW)

SPARK_URL = 'https://api.ciscospark.com/v1'
ROOM_NAME = 'ERNA'

ASAv_URL = 'https://172.16.11.5'
ASAv_USER = 'python'
ASAv_PASSW = 'cisco'
ASAv_AUTH = HTTPBasicAuth(ASAv_USER, ASAv_PASSW)

ASAv_CLIENT = '172.16.41.55'
ASAv_REMOTE_CLIENT = '172.16.203.50'

UCSD_URL = 'https://https://10.94.132.69'
UCSD_USER = 'gzapodea'
UCSD_PASSW = 'cisco.123'
UCSD_KEY = '1D3FD49A0D474481AE7A4C6BD33EC82E'
UCSD_CONNECT_FLOW = 'Gabi_VM_Connect_VLAN_10'
UCSD_DISCONNECT_FLOW = 'Gabi_VM_Disconnect_VLAN_10'



def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data:
    :return:
    """

    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))


def create_spark_room(room_name):
    """
    Action:     this function will create a Spark room with the title room name
    Call to:    Spark - /rooms
    Input:      the room name, global variable - Spark auth access token
    Output:     the Spark room Id
    """

    payload = {'title': room_name}
    url = SPARK_URL + '/rooms'
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    room_response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    room_json = room_response.json()
    room_number = room_json['id']
    print('Created Room with the name :  ', ROOM_NAME)
    return room_number


def find_spark_room_id(room_name):
    """
    Action:     this function will find the Spark room id based on the room name
    Call to:    Spark - /rooms
    Input:      the room name, global variable - Spark auth access token
    Output:     the Spark room Id
    """

    payload = {'title': room_name}
    room_number = None
    url = SPARK_URL + '/rooms'
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    room_response = requests.get(url, data=json.dumps(payload), headers=header, verify=False)
    room_list_json = room_response.json()
    room_list = room_list_json['items']
    for rooms in room_list:
        if rooms['title'] == room_name:
            room_number = rooms['id']
    return room_number


def add_spark_room_membership(room_Id, email_invite):
    """
    Action:     this function will add membership to the Spark room with the room Id
    Call to:    Spark - /memberships
    Input:      room Id and email address to invite, global variable - Spark auth access token
    Output:     none
    """

    payload = {'roomId': room_Id, 'personEmail': email_invite, 'isModerator': 'true'}
    url = SPARK_URL + '/memberships'
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    print("Invitation sent to :  ", email_invite)


def last_spark_room_message(room_Id):
    """
    Action:     this function will find the last message from the Spark room with the room Id
    Call to:    Spark - /messages
    Input:      room Id, global variable - Spark auth access token
    Output:     last room message and person email
    """

    url = SPARK_URL + '/messages?roomId=' + room_Id
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    response = requests.get(url, headers=header, verify=False)
    list_messages_json = response.json()
    list_messages = list_messages_json['items']
    last_message = list_messages[0]['text']
    last_person_email = list_messages[0]['personEmail']
    print('Last room message :  ', last_message)
    print('Last Person Email', last_person_email)
    return [last_message, last_person_email]


def post_spark_room_message(room_id, message):
    """
    Action:     this function will post a message to the Spark room with the room Id
    Call to:    Spark - /messages
    Input:      room Id and the message, global variable - Spark auth access token
    Output:     none
    """

    payload = {'roomId': room_id, 'text': message}
    url = SPARK_URL + '/messages'
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    print("Message posted :  ", message)


def delete_spark_room(room_id):
    """
    Action:     this function will delete the Spark room with the room Id
    Call to:    Spark - /rooms
    Input:      room Id, global variable - Spark auth access token
    Output:     none
    """

    url = SPARK_URL + '/rooms/' + room_id
    header = {'content-type': 'application/json', 'authorization': SPARK_AUTH}
    requests.delete(url, headers=header, verify=False)
    print("Deleted Spark Room :  ", ROOM_NAME)


def get_ucsd_api_key():
    """
    Create a UCSD user api key for authentication of the UCSD API's requests
    Call to UCSD, /app/api/rest?formatType=json&opName=getRESTKey&user=
    :return: the UCSD user API Key
    """

    url = UCSD_URL + '/app/api/rest?formatType=json&opName=getRESTKey&user=' + UCSD_USER + '&password=' + UCSD_PASSW
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    UCSD_api_key_json = requests.get(url, headers=header, verify=False)
    UCSD_api_key = UCSD_api_key_json.json()
    print ('api key: ', UCSD_api_key)
    return UCSD_api_key


def execute_ucsd_workflow(UCSD_key, workflow_name):
    """
    Execute an UCSD workflow
    Call to UCSD, /app/api/rest?formatType=json&opName=userAPISubmitWorkflowServiceRequest&opData=
    :param UCSD_key: UCSD user API key
    :param workflow_name: workflow name, parameters if needed
    :return:
    """
    url = UCSD_URL + '/app/api/rest?formatType=json&opName=userAPISubmitWorkflowServiceRequest&opData={param0:"' + workflow_name + '", param1: {}, param2:-1}'
    print ('url: ', url)
    header = {'content-type': 'application/json', 'accept-type': 'application/json', "X-Cloupia-Request-Key": UCSD_key}
    response = requests.post(url=url, headers=header, verify=False)
    print(response.text)


def get_service_ticket():
    """
    create the authorization ticket required to access APIC-EM
    Call to APIC-EM - /ticket
    :return: ticket
    """

    ticket = None
    payload = {'username': EM_USER, 'password': EM_PASSW}
    url = EM_URL + '/ticket'
    header = {'content-type': 'application/json'}
    ticket_response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    if not ticket_response:
        print('No data returned!')
    else:
        ticket_json = ticket_response.json()
        ticket = ticket_json['response']['serviceTicket']
        print('APIC-EM ticket: ', ticket)
        return ticket


def locate_client_apic_em(client_IP,ticket):
    """
    Locate a wired client device in the infrastructure by using the client IP address
    Call to APIC-EM - /host
    :param client_IP: Client IP Address
    :param ticket: APIC-EM ticket
    :return: hostname, interface_name, vlan_Id
    """

    interface_name = None
    hostname = None
    host_info = None
    vlan_Id = None
    url = EM_URL + '/host'
    header = {'accept': 'application/json', 'X-Auth-Token': ticket}
    payload = {'hostIp': client_IP}
    host_response = requests.get(url, params=payload, headers=header, verify=False)
    host_json = host_response.json()
    if host_json['response'] == []:
        print('The IP address ', client_IP, ' is not used by any client devices')
    else:
        host_info = host_json['response'][0]
        host_type = host_info['hostType']
        interface_name = host_info['connectedInterfaceName']
        device_id = host_info['connectedNetworkDeviceId']
        vlan_Id = host_info['vlanId']
        hostname = get_hostname_id(device_id, ticket)[0]
        print('The IP address ', client_IP, ' is connected to the network device ', hostname, ',  interface ', interface_name)
    return hostname, interface_name, vlan_Id


def get_hostname_id(device_id, ticket):
    """
    Find out the hostname of the network device with the specified device ID
    Call to APIC-EM - network-device/{id}
    :param device_id: APIC-EM device Id
    :param ticket: APIC-EM ticket
    :return: hostname and the device type of the network device
    """

    hostname = None
    url = EM_URL + '/network-device/' + device_id
    header = {'accept': 'application/json', 'X-Auth-Token': ticket}
    hostname_response = requests.get(url, headers=header, verify=False)
    hostname_json = hostname_response.json()
    hostname = hostname_json['response']['hostname']
    devicetype =  hostname_json['response']['type']
    return hostname, devicetype


def pi_get_device_id(device_name):
    """
    Find out the PI device Id using the device hostname
    Call to Prime Infrastructure - /webacs/api/v1/data/Devices, filtered using the Device Hostname
    :param device_name: device hostname
    :return: PI device Id
    """

    url = PI_URL + '/webacs/api/v1/data/Devices?deviceName=' + device_name
    header = {'content-type': 'application/json', 'accept': 'application/json'}
    response = requests.get(url, headers=header, verify=False, auth=PI_AUTH)
    device_id_json = response.json()
    device_id = device_id_json['queryResponse']['entityId'][0]['$']
    return  device_id


def pi_deploy_cli_template(device_id,template_name,variable_value):
    """
    Deploy a template to a device through Job
    Call to Prime Infrastructure - /webacs/api/v1/op/cliTemplateConfiguration/deployTemplateThroughJob
    :param device_id: device Prime Infrastructure id
    :param template_name: PI template name
    :param variable_value: variables to send to template in JSON format
    :return: PI job name
    """

    param = {
        'cliTemplateCommand': {
            'targetDevices': {
                'targetDevice': {
                    'targetDeviceID': str(device_id),
                    'variableValues' : {
                        'variableValue' : variable_value
                    }
                }
            },
            'templateName': template_name
        }
    }
    url = PI_URL + '/webacs/api/v1/op/cliTemplateConfiguration/deployTemplateThroughJob'
    header = {'content-type': 'application/json', 'accept': 'application/json'}
    response = requests.put(url, data=json.dumps(param), headers=header, verify=False, auth=PI_AUTH)
    job_json = response.json()
    job_name = job_json['mgmtResponse']['cliTemplateCommandJobResult']['jobName']
    print ('job name: ', job_name)
    return job_name


def get_job_status(job_name):
    """
    Get job status in PI
    Call to Prime Infrastructure - /webacs/api/v1/data/JobSummary, filtered by the job name, will provide the job id
    A second call to /webacs/api/v1/data/JobSummary using the job id
    :param job_name: Prime Infrastructure job name
    :return: PI job status
    """
    #  find out the PI job id using the job name

    url = PI_URL + '/webacs/api/v1/data/JobSummary?jobName=' + job_name
    header = {'content-type': 'application/json', 'accept': 'application/json'}
    response = requests.get(url, headers=header, verify=False, auth=PI_AUTH)
    job_id_json = response.json()
    job_id =job_id_json['queryResponse']['entityId'][0]['$']

    #  find out the job status using the job id

    url = PI_URL + '/webacs/api/v1/data/JobSummary/' + job_id
    header = {'content-type': 'application/json', 'accept': 'application/json'}
    response = requests.get(url, headers=header, verify=False, auth=PI_AUTH)
    job_status_json = response.json()
    #  print(json.dumps(job_status_json, indent=4, separators=(' , ', ' : ')))
    job_status = job_status_json['queryResponse']['entity'][0]['jobSummaryDTO']['resultStatus']
    return job_status


def get_asav_access_list(interface_name):
    """
    Find out the existing ASAv interface Access Control List
    Call to ASAv - /api/access/in/{interfaceId}/rules
    :param interface_name: ASA interface_name
    :return: Access Control List id number
    """

    url = ASAv_URL + '/api/access/in/' + interface_name + '/rules'
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    response = requests.get(url, headers=header, verify=False, auth=ASAv_AUTH)
    acl_json = response.json()
    # print(json.dumps(response.json(), indent=4, separators=(' , ', ' : ')))
    acl_id_number = acl_json['items'][0]['objectId']
    return acl_id_number


def create_asav_access_list(acl_id, interface_name, client_IP):
    """
    Insert in line 1 a new ACL entry to existing interface ACL
    Call to ASAv - /api/access/in/{interfaceId}/rules, post method
    :param acl_id: ASA ACL id number
    :param interface_name: ASA interface_name
    :param client_IP: client IP
    :return: Response Code - 201 if successful
    """

    url = ASAv_URL + '/api/access/in/' + interface_name  + '/rules/' + str(acl_id)
    header = {'content-type': 'application/json', 'accept-type':'application/json'}

    post_data = {
        'sourceAddress': {
            'kind': 'IPv4Address',
            'value': ASAv_REMOTE_CLIENT
        },
        'destinationAddress': {
            'kind': 'IPv4Address',
            'value': client_IP
        },
        'sourceService': {
            'kind': 'NetworkProtocol',
            'value': 'ip'
        },
        'destinationService': {
            'kind': 'NetworkProtocol',
            'value': 'ip'
        },
        'permit': True,
        'active': True,
        'ruleLogging': {
            'logStatus': 'Informational',
            'logInterval': 300
        },
        'position': 1,
        'isAccessRule': True
    }
    response = requests.post(url, json.dumps(post_data), headers=header, verify=False, auth=ASAv_AUTH)
    return(response.status_code)


def delete_asav_access_list(acl_id, interface_name):
    """
    Delete ACL entry line 1 to existing interface ACL
    Call to ASAv - /api/access/in/{interfaceId}/rules, delete method
    :param acl_id: ASA ACL id number
    :param interface_name: ASA interface_name
    :return: Response Code - None if successful
    """

    url = ASAv_URL + '/api/access/in/' + interface_name + '/rules/'+str(acl_id)
    header = {'content-type': 'application/json', 'accept-type': 'application/json'}
    response = requests.delete(url, headers=header, verify=False, auth=ASAv_AUTH)


def main():
    """
    Vendor will join Spark Room with the name {ROOM_NAME}
    It will ask for access to an IP-enabled device - named {IPD}
    The code will map this IP-enabled device to the IP address {172.16.41.55}
    Access will be provisioned to allow connectivity from DMZ VDI to IPD
    """

    # verify if Spark Room exists, if not create Spark Room, and add membership (optional)

    spark_room_id = find_spark_room_id(ROOM_NAME)
    if spark_room_id is None:
        spark_room_id = create_spark_room(ROOM_NAME)
        # add_spark_room_membership(spark_room_id, IT_ENG_EMAIL)
        print('- ', ROOM_NAME, ' -  Spark room created')
        post_spark_room_message(spark_room_id, 'To require access enter :  IPD')
        post_spark_room_message(spark_room_id, 'Ready for input!')
        print('Instructions posted in the room')
    else:
        print('- ', ROOM_NAME, ' -  Existing Spark room found')
        post_spark_room_message(spark_room_id, 'To require access enter :  IPD')
        post_spark_room_message(spark_room_id, 'Ready for input!')
    print('- ', ROOM_NAME, ' -  Spark room id: ', spark_room_id)

    # check for messages to identify the last message posted and the user's email who posted the message
    # check for the length of time required for access

    last_message = last_spark_room_message(spark_room_id)[0]

    while last_message == 'Ready for input!':
        time.sleep(5)
        last_message = last_spark_room_message(spark_room_id)[0]
        if last_message == 'IPD':
            last_person_email = last_spark_room_message(spark_room_id)[1]
            post_spark_room_message(spark_room_id, 'How long time do you need access for? (in minutes)  : ')
            time.sleep(10)
            if last_spark_room_message(spark_room_id)[0] == 'How long time do you need access for? (in minutes)  : ':
                timer = 30 * 60
            else:
                timer = int(last_spark_room_message(spark_room_id)[0]) * 60
        elif last_message != 'Ready for input!':
            post_spark_room_message(spark_room_id, 'I do not understand you')
            post_spark_room_message(spark_room_id, 'To require access enter :  IPD')
            post_spark_room_message(spark_room_id, 'Ready for input!')
            last_message = 'Ready for input!'

    # get UCSD API key

    ucs_key = get_ucsd_api_key()

    # execute UCSD workflow to connect VDI to VLAN, power on VDI
    execute_ucsd_workflow(ucs_key, UCSD_CONNECT_FLOW)

    # get the APIC-EM auth ticket

    EM_ticket = get_Service_Ticket()

    # client IP address - DNS lookup if available

    client_IP = '172.16.41.55'

    # locate IPD in the environment using APIC-EM

    client_connected = locate_client_apic_em(client_IP,EM_ticket)

    #  deploy DC router CLI template

    dc_device_hostname = 'PDX-RO'
    PI_dc_device_id = pi_get_device_id(dc_device_hostname)
    print ('Head end router: ', dc_device_hostname, ', PI Device id: ',PI_dc_device_id)
    template_name = 'GREDConfig'
    variable_value = None  #  the template does not require any variables
    PI_dc_job_name = pi_deploy_cli_template(PI_dc_device_id, template_name, variable_value)

    #  deploy remote router CLI template

    remote_device_hostname = client_connected[0]
    vlan_number = client_connected[2]
    print('Client connected to switch: ', remote_device_hostname, ' VLAN: ', vlan_number)
    PI_remote_device_id = pi_get_device_id(remote_device_hostname)
    print ('Remote Router: ', remote_device_hostname, ', PI device Id: ', PI_remote_device_id)
    template_name = 'GRERConfig'
    variable_value = [
        {'name' : 'RemoteClient', 'value' : client_IP},{'name' : 'VlanId', 'value' : str(vlan_number)}
    ]
    PI_remote_job_name = pi_deploy_cli_template(PI_remote_device_id,template_name,variable_value)

    # check for job status

    time.sleep(60)  #  time delay to allow PI de deploy the jobs
    dc_job_status = get_job_status(PI_dc_job_name)
    print ('DC CLI template deployment status: ', dc_job_status)
    remote_job_status = get_job_status(PI_remote_job_name)
    print ('Remote CLI template deployment status: ', remote_job_status)

    #  create ASAv outside interface ACL to allow traffic

    ASAv_interface = 'outside'
    acl_id = get_asav_access_list(ASAv_interface)
    create_status_code = create_asav_access_list(acl_id, ASAv_interface, client_IP)
    if (create_status_code == 201):
        print('ASAv access list created to allow traffic from ', ASAv_REMOTE_CLIENT, ' to ', client_IP)
    else:
        print('Error creating the ASAv access list to allow traffic from ', ASAv_REMOTE_CLIENT, ' to ', client_IP)

    # timer required to maintain the ERNA enabled, user provided

    time.sleep(timer)

    #  restore configurations

    #  restore DC router config

    dc_device_hostname = 'PDX-RO'
    PI_dc_device_id = pi_get_device_id(dc_device_hostname)
    print ('Head end router: ', dc_device_hostname, ', PI Device id: ',PI_dc_device_id)
    template_name = 'GREDDelete'
    variable_value = None  #  the template does not require any variables
    PI_dc_job_name = pi_deploy_cli_template(PI_dc_device_id, template_name, variable_value)

    #  restore remote router CLI template

    remote_device_hostname = client_connected[0]
    vlan_number = client_connected[2]
    print('Client connected to switch: ', remote_device_hostname, ' VLAN: ', vlan_number)
    PI_remote_device_id = pi_get_device_id(remote_device_hostname)
    print ('Remote Router: ', remote_device_hostname, ', PI device Id: ', PI_remote_device_id)
    template_name = 'GRERDelete'
    variable_value = [
        {'name' : 'RemoteClient', 'value' : client_IP},{'name' : 'VlanId', 'value' : str(vlan_number)}
    ]
    PI_remote_job_name = pi_deploy_cli_template(PI_remote_device_id,template_name,variable_value)
    time.sleep(60)  #  time delay to allow PI de deploy the jobs
    dc_job_status = get_job_status(PI_dc_job_name)
    print ('DC router restore configurations status: ', dc_job_status)
    remote_job_status = get_job_status(PI_remote_job_name)
    print ('Remote router restore configurations status: ', remote_job_status)

    # delete ASAv line 1 ACL created to allow traffic

    acl_id2 = get_asav_access_list(ASAv_interface)
    delete_status_code = delete_asav_access_list(acl_id2,ASAv_interface)
    if (delete_status_code == None):
        print ('ASAv access list allowing traffic from ', ASAv_REMOTE_CLIENT, ' to ', client_IP, ' deleted')
    else:
        print ('Error deleting the ASAv access list allowing traffic from ', ASAv_REMOTE_CLIENT, ' to ', client_IP)


if __name__ == '__main__':
    main()


