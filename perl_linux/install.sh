#!/bin/bash

USER="spore"
SYSTEMDIR=/usr/local/lib/systemd/system
SPORESCRIPT="spore-seeder.pl"
SPORESRV="spore-seeder"
LOCAL_DIR=$HOME/.spore-seeder/bin

local_install () {
  echo "Local installation ..."
  mkdir -p $LOCAL_DIR
  cp $SPORESCRIPT $LOCAL_DIR/.
  cp ../perl_common/SporeCommon.pm $LOCAL_DIR/.
  rm $LOCAL_DIR/$SPORESRV 2> /dev/null
  ln -s $LOCAL_DIR/$SPORESCRIPT $LOCAL_DIR/$SPORESRV
  echo "export PATH=\$PATH:$LOCAL_DIR" >> ~/.profile
  . ~/.profile
  echo "spore-seeder installed in $HOME/.spore-seeder/bin"
  exit 0
}

# This script does not work on OpenBSD.
OSNAME=$(uname)
if [[ "$OSNAME" =~ "OpenBSD" ]];
then
    echo "This installation script does not support OpenBSD. Run install_bsd.sh instead."
    exit 1
fi

if [[ "$1" = "--local" ]];
then
    local_install
fi

# Differences between Ubuntu and Red Hat
OSVERSION=$(cat /proc/version)
ADDUSERGROUP=--ingroup
if [[ "$OSVERSION" =~ "Red Hat" ]];
then
    ADDUSERGROUP=--groups
fi

# Copy files
mkdir -p /etc/spore-seeder
cp spore-seeder-service.config /etc/spore-seeder/.

mkdir -p /usr/local/share/spore-seeder
cp spore-seeder.pl /usr/local/share/spore-seeder/.
cp ../perl_common/SporeCommon.pm /usr/local/share/spore-seeder/.
chmod a+x /usr/local/share/spore-seeder/spore-seeder.pl

# Create user
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