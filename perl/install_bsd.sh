#!/bin/ksh

# This script does not work on Linux.
OSNAME=$(uname)
if [[ "$OSNAME" =~ "Linux" ]];
then
    echo "This installation script does not support Linux. Run install.sh instead."
    exit 1
fi

USER="spore"
SPORESRV="spore-seeder"


# Copy files
mkdir -p /usr/local/etc/spore-seeder
cp spore-seeder-service-bsd.config /usr/local/etc/spore-seeder/.

cp spore-seeder.pl /usr/sbin/.
chmod a+x /usr/sbin/spore-seeder.pl

cp sporeseeder /etc/rc.d/sporeseeder
rcctl enable sporeseeder
rcctl start sporeseeder
