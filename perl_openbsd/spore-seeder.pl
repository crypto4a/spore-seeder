#!/usr/bin/perl
#
# MIT License
#
# Copyright (c) 2018-2019 Crypto4A Technologies Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

use strict;
use warnings;

use HTTP::Tiny;
use JSON::PP;
use MIME::Base64 qw(decode_base64url);
use Data::Dumper;
use Getopt::Long;

use FindBin;
use lib $FindBin::Bin;
use lib '../perl_common';
use SporeCommon;

my $SERVICE_CONFIG = "/etc/spore-seeder/spore-seeder-service.config";


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
	my $entropy_string = SporeCommon::mix_entropy($result->{'entropy'});
	return contribute_entropy($result, $entropy_string, $verbose);
}

sub do_query {
	my ($URL, $certChainURL, $info, $certchain, $service, $verbose, $validateSig, $autoSeed, $threshold) = @_;
	my $certificateChain = "";
	my @claims;
	my $challenge;
	my $window = 60;
	my $time;

	$challenge = sprintf("%08X", rand(0xffffffff));
	$time = time();
	my $result = SporeCommon::get_entropy($URL, $challenge);
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
		my $pkresult = SporeCommon::get_entropy($certChainURL, $pkchallenge);
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
		if (!SporeCommon::validate_signature(\@claims, $verbose, $certificateChain)) {
			printf("Error: signature verification failed.\n");
		}
	} elsif ($verbose) {
		print "Skip signature validation.\n";
	}

	if (!SporeCommon::check_claims(\@claims, $result, $certificateChain, $challenge, $verbose)) {
		if ($service) {
			return;
		}
		exit 1;
	}

	add_entropy($result, $verbose);
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

SporeCommon::get_options(\$certchain, \$info, \$verbose, \$help,
	\$service, \$opt_url, \$skip_sig_validate);

if ($certchain && $info) {
	print "Error: --certificate (-c) and --info (-i) cannot be specified togother.\n";
	SporeCommon::usage(1);
}

if ($certchain && $service) {
	print "Error: --certificate (-c) and --service (-s) cannot be specified togother.\n";
	SporeCommon::usage(1);
}

if ($info && $service) {
	print "Error: --info (-i) and --service (-s) cannot be specified togother.\n";
	SporeCommon::usage(1);
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
	my %service_config = %{SporeCommon::parse_config($SERVICE_CONFIG)};
	$verbose = SporeCommon::is_true($service_config{'verbose'});
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
	my $entropyURL = "http://$sporeServer/eaasp/getEntropy";
	if ($service_config{'address'}) {
		$entropyURL = "http://$service_config{'address'}/eaasp/getEntropy";
		if ($verbose) {
			print "spore-seeder service url: " . $entropyURL . "\n";
		}
	}
	while (1) {
		my $validateSig = SporeCommon::is_true($service_config{'verify'});
		do_query($entropyURL, $certChainURL, $info, $certchain, $service, $verbose, $validateSig);
		sleep($pollInterval);
	}
} else {
	do_query($URL, $certChainURL, $info, $certchain, $service, $verbose, !$skip_sig_validate);
}
