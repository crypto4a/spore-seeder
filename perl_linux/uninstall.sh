#!/bin/bash

# $USER_PWD gets the path of the folder from which the self-extracting script
# is executed.

USER="spore"
SYSTEMDIR=/usr/local/lib/systemd/system
SPORESRV="spore-seeder"

# Remove spore-seeder config.
rm -rf /etc/spore-seeder

# Remove spore-seeder script
rm -rf /usr/local/share/spore-seeder

# Remove service
if [ -e "$SYSTEMDIR/${SPORESRV}.service" ]
then
    systemctl stop $SPORESRV
    systemctl disable $SPORESRV
fi

rm $SYSTEMDIR/${SPORESRV}.service
systemctl daemon-reload

# Remove user
userdel -r $USER
rm -rf /var/cache/$USER

