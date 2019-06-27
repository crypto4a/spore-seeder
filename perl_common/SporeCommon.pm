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
package SporeCommon;

use strict;
use warnings;

use HTTP::Tiny;
use JSON::PP;
use MIME::Base64 qw(decode_base64url);
use Data::Dumper;
use Getopt::Long;

# rng address
my $RNDADDENTROPY = 0x40085203;
my $SERVICE_CONFIG = "/etc/spore-seeder/spore-seeder-service.config";


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
  -f, --config          Set the configuration file. Default: /etc/spore-seeder/spore-seeder-service.config
  -n, --no-sig          Skip signature verification.
  -v, --verbose         Show additional messages.
  -h, --help            Display this information.

EOT
exit $exit_code;
}

#
# Command line options
#
sub get_options {
	my ($certchain, $info, $verbose, $help, $service, $opt_url, $skip_sig_validate, $config) = @_;
	GetOptions(
		"certificate" 	=> $certchain,
		"info"   		=> $info,
		"verbose"  		=> $verbose,
		"help"  		=> $help,
		"service"  		=> $service,
		"url=s"    		=> $opt_url,
		"no-sig"        => $skip_sig_validate,
		"config|f=s"    => $config
	) or usage(1);

	if ($$help) {
		usage(0);
	}
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
