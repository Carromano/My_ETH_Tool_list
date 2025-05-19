#!/bin/bash
cp /root/scripts/database.db /home/app-production/app/instance/database.db
chown app-production:app-production /home/app-production/app/instance/database.db
/usr/sbin/service app-production restart
