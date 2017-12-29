#!/bin/bash

cd ~/templateARM/inventory  

git fetch 

git checkout master

python azure_webapp_rm.py --pretty > webAppInventory.json

python azure_redis_rm.py --pretty > RedisInventory.json

day =  date +%Y-%m-%dT%H:%M:%S

git commit -a -m "Update Inventory $day" 

git push  