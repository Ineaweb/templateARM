#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    with open('/var/lib/awx/projects/_6__z_aim_pmo3_wso_ew1_dev/inventory/fullInventory.json', 'r') as content_file:
        content = content_file.read()
        print(content)

main()
