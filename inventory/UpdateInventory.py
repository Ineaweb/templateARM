#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
	cwd = os.getcwd()
	webapppath = "{0}/webAppInventory.json".format(cwd)
	redispath = "{0}/RedisInventory.json".format(cwd)
    with open(webapppath, 'r') as webapp_file:
        webapp = webapp_file.read()
        print(webapp)		
	with open(redispath, 'r') as redis_file:
        redis = redis_file.read()
        print(redis)	

main()
