#!/usr/bin/perl
# @(#) Script to interrogate and obtain entropy from a Spore server
# @(#) $Revision: 1.31 $

#
# Based on the Crypto4A spore clients at: https://github.com/crypto4a
#

use strict;
use warnings;

use HTTP::Tiny;
use JSON::PP;
use MIME::Base64 qw(decode_base64url);
use Data::Dumper;
use Getopt::Long;

# rng address
my $RNDADDENTROPY = 0x40085203;
my $SERVICE_CONFIG = "/usr/local/etc/spore-seeder/spore-seeder-service.config";

my $OS = `uname`;
if ($OS =~ /OpenBSD/) {
	$SERVICE_CONFIG = "/usr/local/etc/spore-seeder/spore-seeder-service-bsd.config";
}

#
# Usage
#
sub usage {
	my ($exit_code) = @_;
	print <<'EOT';
Usage: perl spore-seeder.pl [option(s)]
 The options are:
  -u, --url             Set the spore server address. Default: rootofqaos.com
  -c, --certificate     Retrieve the Spore server certificate chain.
  -i, --info            Retrieve information about the Spore service.
  -s, --service         Run in service mode.
  -n, --no-sig          Skip signature verification.
  -v, --verbose         Show additional messages.
  -h, --help            Display this information.

EOT
exit $exit_code;
}

sub is_true {
	my ($value) = @_;
	if (!$value) {
		return 0;
	}
	return uc($value) eq 'TRUE';
}

sub parse_config {
	my ($config) = @_;
	open my $in, '<', $config or die $!;
	my %data;
	while (<$in>) {
		chomp;
		# Skip comment
  		next if /^#/;

		# Skip blank line
		next if /^\s*$/;

		if (/^(\w+)\s*=\s*(.*)/) {
    		my ($key, $value) = ($1, $2);
    		$data{$key} = $value
  		} else {
    		print STDERR "Invalid config format: $_\n";
  		}
	}
	return \%data;
}

#
# get entropy from the Spore server
#
sub get_entropy {
	my ($url, $ch) = @_;
	my $ua = HTTP::Tiny->new;
	my $data = { challenge => $ch };
	my $params = $ua->www_form_urlencode($data);
	my $response = $ua ->post($url . '/?' . $params);

	if($response->{'status'} != '200') {
		print "Error: status = $response->{'status'}\n";
		return 1;
	}

	my $decoded = decode_json($response->{'content'});
	return $decoded;
}

#
# mix entropy from the Spore server with local random before seeding
#
sub mix_entropy {
	my ($entropy) = @_;
	my $decoded = unpack('H*', decode_base64url($entropy));
	my $length = length($decoded);
	my @entropy = ($decoded =~ /(..)/g);

	my @local;
	my @mixed;
	my $z = 0;
	while($z < $length/2) {
		$local[$z] = rand(0xff);
		$mixed[$z] = hex($entropy[$z]) & int($local[$z]);
		$mixed[$z] = $mixed[$z] ^ int($local[$z]);
		$z++;
	}

	#
	# create a new string of mixed entropy
	#
	my $entropy_string = "";
	foreach(@entropy) {
		$entropy_string = sprintf("%s%s", $_, $entropy_string);
	}
	return $entropy_string;
}

#
# convert the claim signature to DER and write to file
#
sub write_signature_file {
	my ($raw, $sigfile) = @_;

	open(FH, '>:raw', $sigfile) or die $!;
	my $padR = vec($raw, 0, 8) >= 128;
	my $padS = vec($raw, 32, 8) >= 128;

	# Sequence
	print FH pack("H*", "30");

	# Length, R and S each has 32 byte. Each has 1 byte tag and length.
	my $totalLen = 68;
	if ($padR) {
	    $totalLen ++;
	}
	if ($padS) {
	    $totalLen ++;
	}
	print FH pack("C*", $totalLen);

	# R tag
	print FH pack("H*", "02");
	# R length 32
	my $RLen = 32;
	if ($padR) {
	    $RLen ++;
	}
	print FH pack("C*", $RLen);
	# R
	if ($padR) {
	    print FH pack("H*", "00");
	}
	print FH (substr $raw, 0, 32);

	# S tag
	print FH pack("H*", "02");
	# S length 32
	my $SLen = 32;
	if ($padS) {
	    $SLen ++;
	}
	print FH pack("C*", $SLen);
	# S
	if ($padS) {
	    print FH pack("H*", "00");
	}
	print FH (substr $raw, 32, 32);
	close FH or die $!;
}

#
# Validate signature
#
sub validate_signature {
	my @claims = @{$_[0]};
	my $verbose = $_[1];
	my $certificateChain = $_[2];

	#
	# write the certificate chain file
	#
	my $certfile = "/tmp/certificateChain.$$";
	open(FH, '>', $certfile) or die $!;
	print FH $certificateChain;
	close FH or die $!;

	#
	# write the public key to file
	#
	my $keyfile = "/tmp/pubkey.$$";
	system("openssl x509 -in $certfile -pubkey -noout > $keyfile");
	if($? != 0) {
		printf("Error: unable to generate key from certificate chain.\n");
		return 0;
	}

	#
	# write the base64url encoded JWT "header" + "." + "payload" to file
	#
	my $tfile = "/tmp/tfile.$$";
	open(FH, '>', $tfile) or die $!;
	print FH "$claims[0].$claims[1]";
	close FH or die $!;

	#
	# write DER encoded signature to file
	#
	my $sigfile = "/tmp/sigfile.$$";
	write_signature_file(decode_base64url($claims[2]), $sigfile);

	#
	# perform signature verification
	#
	my $r=`openssl dgst -sha384 -verify $keyfile -signature $sigfile $tfile`;
	if($r !~ /Verified OK/) {
		printf("r = %s\n", $r);
		printf("Error: unable to verify signature.\n");
		return 0;
	} else {
		if($verbose == 1) {
			printf("Claims signature verified successfully.\n");
		}
	}

	#
	# delete temporary files (comment out these lines for debugging)
	#
	foreach ($certfile, $keyfile, $sigfile, $tfile) {
		unlink $_ or warn $!;
	}
	return 1;
}

#
# Contribute the entropy without increasing entropy estimate.
#
sub contribute_entropy {
	my ($result, $entropy_string, $verbose) = @_;
	if(defined $result->{'entropy'}) {
		my $filename = '/dev/urandom';
		if(not -w $filename) {
			printf("Warning: $filename is not writable.\n");
			printf("Warning: displaying (mixed) entropy for future use:\n");
			printf("%s\n", $entropy_string);
			exit 1;
		} else {
			if($verbose == 1) {
				printf("Seeding entropy to /dev/urandom.\n");
			}
			open(FH, '>', $filename) or die $!;
			print FH $entropy_string;
			close FH;
		}
	}
}


sub add_entropy {
	my ($result, $verbose) = @_;
	if($verbose) {
		printf("Mixing entropy from Spore server with local random.\n");
	}
	my $entropy_string = mix_entropy($result->{'entropy'});

	if (!open(RD, ">>/dev/random")) {
		printf "Error: cannot open /dev/random for writing.\n";
		# fall back to contribution only.
		return contribute_entropy($result, $entropy_string, $verbose);
	}

	# Try to add entropy and increase the reading.
	my $size = length($entropy_string);
	my $entropy_pack = pack("i i a".$size, $size * 8, $size, $entropy_string);
	if (!ioctl(RD, $RNDADDENTROPY, $entropy_pack)) {
		if ($verbose) {
			printf "Error: failed to perform ioctl with RNDADDENTROPY.\n";
		}
		close RD;
		# fall back to contribution only.
		return contribute_entropy($result, $entropy_string, $verbose);
	} elsif ($verbose) {
		printf "Successfully add entropy through ioctl with RNDADDENTROPY.\n";
	}
	close RD;
}

sub check_claims {
	my ($claims_ref, $result, $certificateChain, $challenge, $verbose) = @_;
	my @claims = @{$claims_ref};

	#
	# confirm response matchs signed claims
	#
	my $claims_decoded = decode_base64url($claims[1]);
	my $signed_json = decode_json($claims_decoded);

	#
	# getCertChain
	#
	if(defined $signed_json->{'certificateChain'}) {
		#
		# signed certificateChain
		#
		if($certificateChain ne $signed_json->{'certificateChain'}) {
			printf("Error: signed certificateChain does not match.\n");
			return 0;
		}
		# nothing else to do for a getCertChain request
		return 1;
	}

	#
	# getEntropy
	#
	if(defined $signed_json->{'challenge'}) {
		#
		# signed challenge
		#
		if($challenge ne $signed_json->{'challenge'}) {
			printf("Error: signed challenge does not match.\n");
			return 0;
		} else {
			if($verbose == 1) {
				printf("Signed challenge matches ($challenge).\n");
			}
		}

		#
		# signed timestamp
		#
		if($result->{'timestamp'} ne $signed_json->{'timestamp'}) {
			printf("Error: signed timestamp does not match.\n");
			return 0;
		} else {
			if($verbose == 1) {
				printf("Signed timestamp matches ($result->{'timestamp'}).\n");
			}
		}

		#
		# signed entropy
		#
		if($result->{'entropy'} ne $signed_json->{'entropy'}) {
			printf("Error: signed entropy does not match.\n");
			return 0;
		} else {
			$result->{'entropy'} =~ s/=$//g;
			if($verbose == 1) {
				printf("Signed entropy matches ($result->{'entropy'}).\n");
			}
		}
	} # end getEntropy
	return 1;
}

# Read the value of /proc/sys/kernel/random/entropy_avail
# Note: does not work on BSD OS.
sub avail_entropy {
	my ($verbose) = @_;
	my $level = 5000;
	if (!open(LEVEL,"/proc/sys/kernel/random/entropy_avail")) {
		print "Failed to read /proc/sys/kernel/random/entropy_avail";
		return;
	}
	$level = <LEVEL>;
	close(LEVEL);
	chomp($level);
	if ($verbose) {
		print "Current avail entropy: " . $level . "\n";
	}
	return $level;
}

sub do_query {
	my ($URL, $certChainURL, $info, $certchain, $service, $verbose, $validateSig, $autoSeed, $threshold) = @_;
	my $certificateChain = "";
	my @claims;
	my $challenge = sprintf("%08X", rand(0xffffffff));
	my $window = 60;
	my $time = time();

	if ($autoSeed) {
		my $entropy = avail_entropy($verbose);
		if (int($entropy) > int($threshold)) {
			return;
		} elsif ($verbose) {
			print "Below threshold " . $threshold . ". Start seeding ...\n";
		}
	}

SEED:
	my $result = get_entropy($URL, $challenge);
	if($result == 1) {
		printf("Error: Failed to contact spore server: $URL\n");
		exit 1;
	}

	#
	# getInfo: no JSON web token claims to verify, no challenge or timestamp
	#
	if($info == 1) {
		if($result->{'entropySize'} =~ /^\d+/) {
			printf("%s:", $result->{'name'});
			printf("%s:", $result->{'entropySize'});
			printf("%s:", $result->{'signingMechanism'} // "");
			printf("\n");
			# exit as there are no claims to process
			exit 0;
		} else {
			printf("Error: unable to process getInfo request.\n");
			exit 1;
		}
	}

	#
	# getCertChain and getEntropy both have JSON web token claims
	#
	my $JWT = $result->{'JWT'} // "";

	if($JWT) {
		#
		# $claims[0] = header
		# $claims[1] = payload
		# $claims[2] = signature
		#
		@claims = split(/\./, "$JWT");
	}

	#
	# always validate signed responses
	# if we don't yet have it, get the public key for signature validation
	#
	if(defined $result->{'certificateChain'}) {
		$certificateChain = $result->{'certificateChain'};
	} else {
		my $pkchallenge = sprintf("%08X", rand(0xffffffff));
		my $pkresult = get_entropy($certChainURL, $pkchallenge);
		$certificateChain = $pkresult->{'certificateChain'};
	}

	if($certchain == 1) {
		if(defined $certificateChain) {
			printf("%s", $certificateChain);
			# do not exit; we may need to process web tokens
		} else {
			printf("Error: unable to process getCerChain request\n");
			exit 1;
		}
	}

	#
	# check (unsigned) freshness of response as appropriate
	#
	if(defined $result->{'timestsamp'}) {
		if(($result->{'timestamp'} - $time) > $window) {
			printf("Error: stale response from server outside window.\n");
			exit 1;
		}
	}

	#
	# check (unsigned) challenge in response as appropriate
	#
	if(defined $result->{'challenge'}) {
		if($result->{'challenge'} ne $challenge) {
			printf("Error: received challenge does not match request.\n");
			exit 1;
		}
	}

	if ($validateSig) {
		if (!validate_signature(\@claims, $verbose, $certificateChain)) {
			printf("Error: signature verification failed.\n");
		}
	} elsif ($verbose) {
		print "Skip signature validation.\n";
	}

	if (!check_claims(\@claims, $result, $certificateChain, $challenge, $verbose)) {
		if ($service) {
			return;
		}
		exit 1;
	}

	add_entropy($result, $verbose);
	if ($autoSeed) {
		my $entropy = avail_entropy($verbose);
		if (int($entropy) < int($threshold)) {
			goto SEED;
		} elsif ($verbose) {
			print "Reach threshold " . $threshold . ". Pause auto-seeding.\n";
		}
	}
}

#
# Spore server and URLs
#
my $sporeServer = "rootofqaos.com";
my $infoURL = "http://$sporeServer/eaasp/getInfo";
my $certChainURL = "http://$sporeServer/eaasp/getCertChain";
my $entropyURL = "http://$sporeServer/eaasp/getEntropy";

my $certchain = 0;
my $info = 0;
my $verbose = 0;
my $service = 0;
my $help = 0;
my $opt_url = '';
my $URL = "";
my $skip_sig_validate = 0;

GetOptions(
	"certificate" 	=> \$certchain,
	"info"   		=> \$info,
	"verbose"  		=> \$verbose,
	"help"  		=> \$help,
	"service"  		=> \$service,
	"url=s"    		=> \$opt_url,
	"no-sig"        => \$skip_sig_validate
) or usage(1);

if ($help) {
	usage(0);
}

if ($certchain && $info) {
	print "Error: --certificate (-c) and --info (-i) cannot be specified togother.\n";
	usage(1);
}

if ($certchain && $service) {
	print "Error: --certificate (-c) and --service (-s) cannot be specified togother.\n";
	usage(1);
}

if ($info && $service) {
	print "Error: --info (-i) and --service (-s) cannot be specified togother.\n";
	usage(1);
}

if ($opt_url) {
	$infoURL = "http://$opt_url/eaasp/getInfo";
	$certChainURL = "http://$opt_url/eaasp/getCertChain";
	$entropyURL = "http://$opt_url/eaasp/getEntropy";
}

$URL = $entropyURL;

if ($info) {
	$URL = $infoURL;
}

if ($certchain) {
	$URL = $certChainURL;
}

if($verbose == 1) {
	printf("Using Spore server: %s\n", $opt_url || $sporeServer);
}

if ($service) {
	my %service_config = %{parse_config($SERVICE_CONFIG)};
	$verbose = is_true($service_config{'verbose'});
	if ($verbose) {
		print "Service Config:\n";
		print Dumper(%service_config);
	}
	my $pollInterval = 3; # Default 3 seconds.
	if ($service_config{'pollInterval'}) {
		$pollInterval = $service_config{'pollInterval'};
		if ($verbose) {
			print "spore-seeder service pollInterval: " . $pollInterval . "\n";
		}
	}
	my $autoSeed = 0;
	if (is_true($service_config{'autoSeed'})) {
		$autoSeed = 1;
		if ($verbose) {
			print "spore-seeder service auto seed\n";
		}
	}
	my $threshold = 3800; # Default threshold.
	if ($service_config{'entropyThreshold'}) {
		$threshold = $service_config{'entropyThreshold'};
		if ($verbose) {
			print "spore-seeder entropy threshold: " . $threshold . "\n";
		}
	}
	my $entropyURL = "http://$sporeServer/eaasp/getEntropy";
	if ($service_config{'address'}) {
		$entropyURL = "http://$service_config{'address'}/eaasp/getEntropy";
		if ($verbose) {
			print "spore-seeder service url: " . $entropyURL . "\n";
		}
	}
	while (1) {
		my $validateSig = is_true($service_config{'verify'});
		do_query($entropyURL, $certChainURL, $info, $certchain, $service, $verbose, $validateSig, $autoSeed, $threshold);
		if ($autoSeed) {
			# Sleep 0.5 second before checking the entropy.
			select(undef, undef, undef, 0.5);
		} else {
			sleep($pollInterval);
		}
	}
} else {
	do_query($URL, $certChainURL, $info, $certchain, $service, $verbose, !$skip_sig_validate);
}
