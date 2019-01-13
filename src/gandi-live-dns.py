#!/usr/bin/env python3
# encoding: utf-8
'''
Gandi v5 LiveDNS - DynDNS Update via REST API and CURL/requests

@author: cave
License GPLv3
https://www.gnu.org/licenses/gpl-3.0.html

Created on 13 Aug 2017
http://doc.livedns.gandi.net/
http://doc.livedns.gandi.net/#api-endpoint -> https://dns.gandi.net/api/v5/
'''

import argparse
import configparser
import json
import requests
import pprint

def get_dynip(ifconfig_provider):
  ''' find out own IPv4 at home <-- this is the dynamic IP which changes more or less frequently
  similar to curl ifconfig.me/ip, see example.config.py for details to ifconfig providers
  '''
  r = requests.get(ifconfig_provider)
  print('Checking dynamic IP: ' , r._contentt.decode("utf-8").strip('\n'))
  return r.contentt.decode("utf-8").strip('\n')

def get_uuid(config, domain):
  '''
  find out ZONE UUID from domain
  Info on domain "DOMAIN"
  GET /domains/<DOMAIN>:

  '''
  url = config["Gandi"]["api_endpoint"] + '/domains/' + domain
  u = requests.get(url, headers={"X-Api-Key":config["Gandi"]["api_secret"]})
  json_object = json.loads(u._content)
  if u.status_code == 200:
    return json_object['zone_uuid']
  else:
    print('Error: HTTP Status Code ', u.status_code, 'when trying to get Zone UUID')
    print(json_object['message'])
    exit()

def get_dnsip(uuid, domain, subdomains, config):
  ''' find out IP from first Subdomain DNS-Record
  List all records with name "NAME" and type "TYPE" in the zone UUID
  GET /zones/<UUID>/records/<NAME>/<TYPE>:

  The first subdomain from config.subdomain will be used to get
  the actual DNS Record IP
  '''

  url = config["Gandi"]["api_endpoint"] + '/zones/' + uuid + '/records/' + subdomains[0] + '/A'
  headers = {"X-Api-Key":config["Gandi"]["api_secret"]}
  u = requests.get(url, headers=headers)
  if u.status_code == 200:
    json_object = json.loads(u._content)
    print('Checking IP from DNS Record' , subdomains[0], domain, ':', json_object['rrset_values'][0].strip('\n'))
    return json_object['rrset_values'][0].strip('\n')
  else:
    print('Error: HTTP Status Code ', u.status_code, 'when trying to get IP from subdomain', subdomains[0])
    print(json_object['message'])
    exit()

def update_records(uuid, dynIP, subdomain, config):
  ''' update DNS Records for Subdomains
    Change the "NAME"/"TYPE" record from the zone UUID
    PUT /zones/<UUID>/records/<NAME>/<TYPE>:
    curl -X PUT -H "Content-Type: application/json" \
                -H 'X-Api-Key: XXX' \
                -d '{"rrset_ttl": 10800,
                     "rrset_values": ["<VALUE>"]}' \
                https://dns.gandi.net/api/v5/zones/<UUID>/records/<NAME>/<TYPE>
  '''
  url = config["Gandi"]["api_endpoint"] + '/zones/' + uuid + '/records/' + subdomain + '/A'
  payload = {"rrset_ttl": config["Gandi"]["ttl"], "rrset_values": [dynIP]}
  headers = {"Content-Type": "application/json", "X-Api-Key":config["Gandi"]["api_secret"]}
  u = requests.put(url, data=json.dumps(payload), headers=headers)
  json_object = json.loads(u._content)

  if u.status_code == 201:
    print('Status Code:', u.status_code, ',', json_object['message'], ', IP updated for', subdomain)
    return True
  else:
    print('Error: HTTP Status Code ', u.status_code, 'when trying to update IP from subdomain', subdomain)
    print(json_object['message'])
    exit()

def main(config_file, force_update, verbosity):
  if verbosity:
    print("verbosity turned on - not implemented by now")

  config = configparser.ConfigParser()
  config.read(config_file)
  dynIP = get_dynip(config["Gandi"]["ifconfig"])
  domains = json.loads(config.get("Gandi","domains"))
  for domain in domains:
    subdomains = json.loads(config.get(domain,"subdomains"))

    #get zone ID from Account
    uuid = get_uuid(config, domain)

    #compare dynIP and DNS IP
    dnsIP = get_dnsip(uuid, domain, subdomains, config)

    if force_update:
      print("Going to update/create the DNS Records for the subdomains")
      for sub in subdomains:
        update_records(uuid, dynIP, sub, config)
    else:
      if dynIP == dnsIP:
        print("IP Address Match - no further action")
      else:
        print("IP Address Mismatch - going to update the DNS Records for the subdomains with new IP", dynIP)
        for sub in subdomains:
          update_records(uuid, dynIP, sub, config)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('-c', '--config', help="config file", action="store_true", default="/etc/gandi.ini")
  parser.add_argument('-v', '--verbose', help="increase output verbosity", action="store_true")
  parser.add_argument('-f', '--force', help="force an update/create", action="store_true")
  args = parser.parse_args()
  main(args.config, args.force, args.verbose)
