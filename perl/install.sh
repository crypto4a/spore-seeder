#!/bin/bash

# This script does not work on OpenBSD.
OSNAME=$(uname)
if [[ "$OSNAME" =~ "OpenBSD" ]];
then
    echo "This installation script does not support OpenBSD. Run install_bsd.sh instead."
    exit 1
fi

# $USER_PWD gets the path of the folder from which the self-extracting script
# is executed.

USER="spore"
SYSTEMDIR=/usr/local/lib/systemd/system
SPORESRV="spore-seeder"

# SRCDIR=$(dirname $0)

# Differences between Ubuntu and Red Hat
OSVERSION=$(cat /proc/version)
ADDUSERGROUP=--ingroup
if [[ "$OSVERSION" =~ "Red Hat" ]];
then
    ADDUSERGROUP=--groups
fi

# Copy files
mkdir -p /usr/local/etc/spore-seeder
cp spore-seeder-service.config /usr/local/etc/spore-seeder/.

mkdir -p /usr/local/share/spore-seeder
cp spore-seeder.pl /usr/local/share/spore-seeder/.
chmod a+x /usr/local/share/spore-seeder/spore-seeder.pl

# Create user
mkdir -p /var/cache/$USER
if ! getent passwd $USER >/dev/null
then
    adduser --system --home /var/cache/$USER $ADDUSERGROUP daemon $USER \
    --shell /bin/false
fi
chown -R $USER /var/cache/$USER

# Create service
mkdir -p $SYSTEMDIR
if [ -e "$SYSTEMDIR/${SPORESRV}.service" ]
then
    systemctl stop $SPORESRV
    systemctl disable $SPORESRV
fi
cp ${SPORESRV}.service $SYSTEMDIR/${SPORESRV}.service

systemctl daemon-reload
systemctl enable $SPORESRV
systemctl start $SPORESRV