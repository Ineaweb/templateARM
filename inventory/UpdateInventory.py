#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    with open('/var/lib/awx/projects/_6__tsf_azure/inventory/RedisInventory.json', 'r') as content_file:
        content = content_file.read()
        print(content)
        
    with open('/var/lib/awx/projects/_6__tsf_azure/inventory/webAppInventory.json', 'r') as content_file:
        content = content_file.read()
        print(content)        

main()
