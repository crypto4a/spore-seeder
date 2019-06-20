#!/bin/ksh

USER="spore"
SPORESRV="spore-seeder"


# Copy files
mkdir -p /usr/local/etc/spore-seeder
cp spore-seeder-service.config /usr/local/etc/spore-seeder/.

cp spore-seeder.pl /usr/sbin/.
cp ../perl_common/SporeCommon.pm /usr/sbin/.
chmod a+x /usr/sbin/spore-seeder.pl

cp sporeseeder /etc/rc.d/sporeseeder
rcctl enable sporeseeder
rcctl start sporeseeder
