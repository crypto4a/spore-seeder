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

#
# Spore server and URLs
#
my $sporeServer = "entropy.2keys.io";
my $infoURL = "http://$sporeServer/eaasp/getInfo";
my $certChainURL = "http://$sporeServer/eaasp/getCertChain";
my $entropyURL = "http://$sporeServer/eaasp/getEntropy";

#
# Usage
#
sub usage {
print <<'EOT';

Error: invalid argument(s).

Usage: perl p [-c] [-i] [-v] [-s]

With no arguments, p will obtain entropy from the Spore server, mix it with
local random, and seeded /dev/urandom. If the user does not have permission to
write to /dev/urandom, the mixed entropy will be displayed for future use.

[-c] retrieve the Spore server certificate chain.
[-i] retrieve information about the Spore service.
[-v] retrieve entropy and seed local random in a verbose manner.
[-s] run the script as a service.

p will attempt to verify signatures whenever possible.

EOT
exit 1;
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

my @claims;
my $certchain = 0;
my $certificateChain = "";
my $info = 0;
my $verbose = 0;
my $service = 0;
my $URL = "";

#
# process command-line arguments
#
if($#ARGV eq 0) {
	if($ARGV[0] =~ /^-c$/) {
			$certchain = 1;
			$URL = $certChainURL;
	} elsif($ARGV[0] =~ /^-cv$/) {
			$certchain = 1;
			$URL = $certChainURL;
			$verbose = 1;
	} elsif($ARGV[0] =~ /^-i$/) {
			$info = 1;
			$URL = $infoURL;
	} elsif($ARGV[0] =~ /^-iv$/) {
			$info = 1;
			$URL = $infoURL;
			$verbose = 1;
	} elsif($ARGV[0] =~ /^-v$/) {
			$verbose = 1;
			$URL = $entropyURL;
	} elsif($ARGV[0] =~ /^-s$/) {
			$service = 1;
			$URL = $entropyURL;
	} else {
		usage();
	}
} elsif($#ARGV > 0) {
	usage();
} else {
	$URL = $entropyURL;
}

my $challenge = sprintf("%08X", rand(0xffffffff));
my $window = 60;
my $time = time();

if($verbose == 1) {
	printf("Using Spore server: %s\n", $sporeServer);
}
my $result = get_entropy($URL, $challenge);
if($result == 1) {
	printf("Error: Failed to contact spore server: $sporeServer\n");
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

#
# validate signature (this is a bit chunky)
#

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
	exit 1;
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
	exit 1;
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
		exit 1;
	}
	# nothing else to do for a getCertChain request
	exit 0;
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
	exit 1;
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
	exit 1;
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
	exit 1;
} else {
	$result->{'entropy'} =~ s/=$//g;
	if($verbose == 1) {
		printf("Signed entropy matches ($result->{'entropy'}).\n");
	}
}

} # end getEntropy

if($verbose) {
	printf("Mixing entropy from Spore server with local random.\n");
}

my $entropy_string = mix_entropy($result->{'entropy'});

#
# write (mixed) entropy to /dev/urandom, or display if no write permissions
#
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
		exit 0;
	}
}
