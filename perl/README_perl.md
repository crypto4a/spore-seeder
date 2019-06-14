Spore Seeder for Perl
====

This is an implementation of spore-seeder in Perl. It can be run as standalone program, or as a system service.

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

Run as System Service
----

To install and run as a system service:

```
sudo ./install.sh
```

The above command will install spore-seeder as a system service and start it. To confirm that the service is runing:

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

To show that auto-seeding is working, deplete the entropy pool by running:
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


Todo
----
Change the simple command line option to the standard GNU command line option.


