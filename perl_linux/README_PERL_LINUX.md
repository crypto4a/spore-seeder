Spore Seeder for Perl
====

This is an implementation of spore-seeder in Perl. It can be run as standalone program, or as a system service.

Commnad Line Options
----

```
Usage: perl spore-seeder.pl [option(s)]
 The options are:
  -u, --url             Set the spore server address. Default: rootofqaos.com
  -c, --certificate     Retrieve the Spore server certificate chain.
  -i, --info            Retrieve information about the Spore service.
  -s, --service         Run in system service mode.
  -n, --no-sig          Skip signature verification.
  -v, --verbose         Show additional messages.
  -h, --help            Display this information.
```

Prerequites
---
The perl version of spore-seeder has been tested on Ubuntu 18.04 and Centos 7.6. For a clean CentOS without Perl, here are the command lines to install Perl and required modules:

```
sudo yum install perl
sudo yum install perl perl-JSON-PP
```


Standalone Program
----

To run spore-seeder as standalone program, run the following command:

```
./spore-seeder.pl
```

It will get the entropy from default server `rootofqaos.com` and add the entropy to `/dev/urandom`.

Use the `-v` option to show informational messages:

```
./spore-seeder.pl -v
```

Use the `-u` option to set the spore server:

```
./spore-seeder.pl -u rootofqaos.com -v
```

Run as System Service
----

To install and run as a system service:

```
sudo ./install.sh
```

The above command installs spore-seeder as a system service and starts service. The service runs as “spore” user. To confirm that the service is running:

```
ps -ef | grep spore
```

To stop the service:
```
systemctl stop spore-seeder
```

To start the service again:
```
systemctl start spore-seeder
```

To view the log of spore-seeder system service:
```
sudo journalctl --unit=spore-seeder | tail
```

By default, spore-seeder monitors the entropy pool by reading the value of `/proc/sys/kernel/random/entropy_avail`.
If the reading is smaller than the threshold, it will start to seed the entropy pool by getting high entropy random data from the server.

To show that auto-seeding is working, drain the entropy pool by running:
```
cat /dev/random
```

Check the entropy pool and it should be quite small:
```
cat /proc/sys/kernel/random/entropy_avail
```

Check spore-seeder is seeding:
```
sudo journalctl --unit=spore-seeder | tail
```

The configuration file is `/usr/local/etc/spore-seeder/spore-seeder-service.config`. Here is an example of the service configuration file:


```
# Default configurations for the Spore Seeder Service

# This is the queried Spore server's address.
address=entropy.2keys.io

# This value indicates whether or not the signature should be verified.
# Set to false if the signature should not be verified.
verify=True

# How often spore-seeder should poll the server, in seconds.
# This value is used when autoSeed is False.
pollInterval=180

# Should seeder monitor the entropy reading and seed it when it is below a threshold.
autoSeed=True

# The threshold of entropy. Seeder will start to seed once entropy reading is
# below this value.
entropyThreshold=3000
```



