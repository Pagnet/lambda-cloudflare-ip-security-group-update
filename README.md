# lambda-cloudflare-ip-security-group-update

Using a Lambda function to automate creating and updating a Security Group of Cloudflares IPv4 and IPv6 addresses.

## Configure triggers using CloudWatch Events

* Schedule expression: rate(1 day)
* Enabled
    
## Function code for cloudflare

* **Python** 2.7

## Environment variables

**key:** PORTS_LIST
**value:** 80,443

**key:** SECURITY_GROUP_ID
**value:** add your security group ids here

If required you can create a custom security group using the below command line:

    aws ec2 create-security-group --group-name cloudflare-access --description "cloudflare IPs access" --vpc-id VPC-ID-GOES-HERE

## Create a custom role

* **Role Name:** cloudflare-ip-security-group-update

Required rule to allow the lambda function to edit the security group, use the content of the _allow-ec2-security-group-role_ file       

## Time out

Set the Timeout to 30 seconds

## Room for improvement

If you happen to find something not to your liking, you are welcome to send a PR.
    
**Ref.:** 

* [https://api.cloudflare.com/client/v4/ips](https://api.cloudflare.com/client/v4/ips)
