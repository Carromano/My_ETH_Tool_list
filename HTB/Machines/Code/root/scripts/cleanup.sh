#!/bin/bash
find /dev/shm/ -mindepth 1 -mmin +10 -delete
find /tmp/ -mindepth 1 -mmin +10 -delete
find /home/martin/ -mindepth 1 -type f -not -name ".*" -mmin +10 -delete
cp -r /root/scripts/backups/* /home/martin/backups
chown martin:martin -R /home/martin/backups
