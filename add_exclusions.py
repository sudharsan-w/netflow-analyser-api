from exclusions import *
import requests
js = [
        {'name':'private',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'10.0.0.0/8',
         'added_by':'default'},
        {'name':'private',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'172.16.0.0/12',
         'added_by':'default'},
        {'name':'private',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'192.168.0.0/16',
         'added_by':'default'},
        {'name':'Loopback',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'127.0.0.0/8',
         'added_by':'default'},
        {'name':'Loopback',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'169.254.0.0/16',
         'added_by':'default'},
        {'name':'Multicast',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'224.0.0.0/4',
         'added_by':'default'},
        {'name':'Multicast',
         'ex_class':'Private Network',
         'ex_type':'IPV4',
         'ex_entity':'240.0.0.0/4',
         'added_by':'default'},
        {'name':'Google DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'8.8.8.8',
         'added_by':'default'},
        {'name':'Cloudflare DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'1.1.1.1',
         'added_by':'default'},
        {'name':'Google DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'8.8.3.4',
         'added_by':'default'},
        {'name':'Cloudflare DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'1.0.0.1',
         'added_by':'default'},
        {'name':'Open DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'208.67.222.222',
         'added_by':'default'},
        {'name':'Open DNS',
         'ex_class':'DNS',
         'ex_type':'IPV4',
         'ex_entity':'208.67.220.220',
         'added_by':'default'},
        {'name':'Private',
         'ex_class':'Private Network',
         'ex_type':'IPV6',
         'ex_entity':'fe80::/10',
         'added_by':'default'},
        {'name':'Private',
         'ex_class':'Private Network',
         'ex_type':'IPV6',
         'ex_entity':'ff00::/8',
         'added_by':'default'},
        {'name':'Private',
         'ex_class':'Private Network',
         'ex_type':'IPV6',
         'ex_entity':'fe80::/10',
         'added_by':'default'},
        {'name':'Private',
         'ex_class':'Private Network',
         'ex_type':'IPV6',
         'ex_entity':'fc00::/8',
         'added_by':'default'},
        {'name':'Private',
         'ex_class':'Private Network',
         'ex_type':'IPV6',
         'ex_entity':'fd00::/8',
         'added_by':'default'},
        ]
for i in js:
    new_ex = Exclusion(
            name=i['name'],
            status='ON',
            status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
            ex_class=i['ex_class'],
            ex_type=i['ex_type'],
            ex_entity=i['ex_entity'],
            added_by=i['added_by'])
    insert_exclusion(new_ex)
    print(new_ex)
AWS_RANGEs_API = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
res = requests.get(AWS_RANGEs_API)
jsondata = res.json()
ex = []
for i in jsondata['prefixes']:
    new_ex = Exclusion(
            name='AWS',
            status='ON',
            status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
            ex_class='Cloud',
            ex_type='IPV4',
            ex_entity=i['ip_prefix'],
            added_by='auto-script',
            meta=i)
    ex.append(new_ex)
for i in jsondata['ipv6_prefixes']:
    new_ex = Exclusion(
            name='AWS',
            status='ON',
            status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
            ex_class='Cloud',
            ex_type='IPV6',
            ex_entity=i['ipv6_prefix'],
            added_by='auto-script',
            meta=i)
    ex.append(new_ex)
bulk_insert_exclusions(ex)
ex = []
Cloudflare_API_IPV4= 'https://www.cloudflare.com/ips-v4/#'
req = requests.get(Cloudflare_API_IPV4)
jsondata = req.text
jsondata = jsondata.split('\n')
for i in jsondata:
    new_ex = Exclusion(name='Cloudflare',
                       status='ON',
                       status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
                       ex_class='Cloud',
                       ex_type='IPV4',
                       ex_entity=i,
                       added_by='auto-script')
    ex.append(new_ex)
Cloudflare_API_IPV6='https://www.cloudflare.com/ips-v6/#'
req = requests.get(Cloudflare_API_IPV6)
jsondata = req.text
jsondata = jsondata.split('\n')
for i in jsondata:
    new_ex = Exclusion(name='Cloudflare',
                       status='ON',
                       status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
                       ex_class='Cloud',
                       ex_type='IPV6',
                       ex_entity=i,
                       added_by='auto-script')
    ex.append(new_ex)
bulk_insert_exclusions(ex)
ex = []
Google_API_Ips = 'https://www.gstatic.com/ipranges/goog.json'
req = requests.get(Google_API_Ips)
jsondata = req.json()
for i in jsondata['prefixes']:
    print(i) 
    new_ex = Exclusion(
            name='Google',
            status='ON',
            status_history=[{'status':'ON','timestamp':datetime.now(timezone.utc)}],
            ex_class='Cloud',
            ex_type=list(i.keys())[0].replace('Prefix','').upper(),
            ex_entity=list(i.values())[0],
            added_by='auto-script'
            )
    ex.append(new_ex)
bulk_insert_exclusions(ex)
