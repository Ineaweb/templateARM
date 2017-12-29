#!/usr/bin/env python

# Python
import json
import os
import re
import sys
import inspect

def main():
    with open('/var/lib/awx/projects/_6__tsf_azure/inventory/webAppInventory.json', 'r') as webapp_file:
        webapp = webapp_file.read()
        print(webapp)		
    with open('/var/lib/awx/projects/_6__tsf_azure/inventory/RedisInventory.json', 'r') as redis_file:
        redis = redis_file.read()
        print(redis)	

main()
