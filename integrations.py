import requests
from dotenv import load_dotenv
import os
env_path = '.env'
load_dotenv(env_path)
def get_entity_info(entity,entity_type):
    API_URL = f'https://demonl.saptanglabs.com/api_/v1/get/entity_info?type_={entity_type}&val={entity}'
    API_KEY = os.environ['API_KEY']
    headers = {
            'X-API-Key':API_KEY}
    res = requests.get(API_URL,headers=headers)
    return res.json()
def alert_withmail(content,addr):
    pass
def alert_sms(content,addr):
    pass
def alert_api_cust(content,addr):
    pass
print(get_entity_info(entity='1.1.1.1',entity_type='IPV4'))
