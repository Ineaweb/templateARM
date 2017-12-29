#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    dir_path = os.path.dirname(__file__)
    webapppath = "{0}/webAppInventory.json".format(dir_path)
    redispath = "{0}/RedisInventory.json".format(dir_path)
    with open(webapppath, 'r') as webapp_file:
        webapp = webapp_file.read()
        print(webapp)		
    with open(redispath, 'r') as redis_file:
        redis = redis_file.read()
        print(redis)	

main()
