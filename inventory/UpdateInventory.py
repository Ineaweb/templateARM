#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    webapppath = "/var/lib/awx/projects/_6__tsf_azure/inventory/webAppInventory.json"
    redispath = "/var/lib/awx/projects/_6__tsf_azure/inventory/RedisInventory.json"
    with open(webapppath, 'r') as webapp_file:
        webapp = webapp_file.read()
        print(webapp)		
    with open(redispath, 'r') as redis_file:
        redis = redis_file.read()
        print(redis)	

main()
