import os
import boto3
import requests


def get_cloudflare_ip_list():
    """
    Call the CloudFlare API to fetch their server IPs used for webhooks

    :rtype: list
    :return: List of IPs
    """
    response = requests.get('https://api.cloudflare.com/client/v4/ips')
    ips = response.json()
    if 'result' in ips and 'ipv4_cidrs' or 'ipv6_cidrs' in ips['result']:
        return (ips['result']['ipv4_cidrs'], ips['result']['ipv6_cidrs'])

    raise ConnectionError("Error loading IPs from CloudFlare")


def get_aws_security_group(group_id):
    """
    Return the defined Security Group

    :param group_id:
    :type group_id: str
    :return:
    """
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group

    raise ConnectionError('Failed to retrieve security group from Amazon')


def check_rule_exists(rules, address, port):
    """
    Check if the rule currently exists

    :param rules:
    :param address:
    :param port:
    :return:
    """
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False

def check_rule_exists_ipv6(rules, address, port):
    """
    Check if the rule currently exists

    :param rules:
    :param address:
    :param port:
    :return:
    """
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False


def add_rule(group, address, port, description):
    """
    Add the IP address and port to the security group

    :param group:
    :param address:
    :param port:
    :param description:
    :return:
    """
    permissions = [
        {
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'IpRanges': [
                {
                    'CidrIp': address,
                    'Description': description,
                }
            ],
        }
    ]
    group.authorize_ingress(IpPermissions=permissions)
    print("Added %s : %i to %s " % (address, port, group.group_id))

def add_rule_ipv6(group, address, port, description):
    """
    Add the IP address and port to the security group

    :param group:
    :param address:
    :param port:
    :param description:
    :return:
    """
    permissions = [
        {
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'Ipv6Ranges': [
                {
                    'CidrIpv6': address,
                    'Description': description,
                }
            ],
        }
    ]
    group.authorize_ingress(IpPermissions=permissions)
    print("Added %s : %i to %s " % (address, port, group.group_id))


def lambda_handler(event, context):
    """
    AWS lambda main func

    :param event:
    :param context:
    :return:
    """
    ports = [int(port) for port in os.environ['PORTS_LIST'].split(",")]
    if not ports:
        ports = [80]

    security_groups = [str(security_group) for security_group in os.environ['SECURITY_GROUP_ID'].split(",")]

    ip_addresses = get_cloudflare_ip_list()
    description = "Authorize CloudFlare access"

    for security_group in security_groups:
        security_group = get_aws_security_group(security_group)
        current_rules = security_group.ip_permissions
        for port in ports:
            for ip_address in ip_addresses[0]:
                if not check_rule_exists(current_rules, ip_address, port):
                    add_rule(security_group, ip_address, port, description)
            for ip_address in ip_addresses[1]:
                if not check_rule_exists_ipv6(current_rules, ip_address, port):
                    add_rule_ipv6(security_group, ip_address, port, description)
