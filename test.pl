use strict;
use Test;

$| = 1;

BEGIN { plan tests => 106; }

use Fwctl;
use Fwctl::RuleSet;

my %fwopts = ( aliases_file	=> "test-data/etc/aliases",
	       interfaces_file  => "test-data/etc/interfaces",
	       rules_file	=> "test-data/etc/rules",
	       accounting_file  => "test-data/log/acct",
	     );

# Starts by testing the find_interface methods
my $fwctl = new Fwctl( %fwopts );

my $if = $fwctl->find_interface( "127.0.0.1" );
ok( $if->{name}, "LOCAL" );
$if = $fwctl->find_interface( "INTERNET" );
ok( $if->{name} , "EXT");
$if = $fwctl->find_interface( "192.168.1.0/24" );
ok( $if->{name}, "INT" );
$if = $fwctl->find_interface( "192.168.4.255" );
ok( $if->{name}, "INT" );
$if = $fwctl->find_interface( "10.10.10.10" );
ok( $if->{name}, "EXT" );
$if = $fwctl->find_interface( "ANY" );
ok( $if->{name}, "ANY" );
$if = $fwctl->find_interface( "192.168.1.2" );
ok( $if->{name}, "INT1" );

# Test the 16 combination for a telnet connection with
# each policy. 
# SRC_ANY		=> ANY
# SRC_LOCAL_IP		=> INT_IP
# SRC_LOCAL_IMPLIED	=> INT_NET
# SRC_REMOTE		=> INT_REM_HOST
# DST_ANY		=> ANY
# DST_LOCAL_IP		=> PERIM_IP
# DST_LOCAL_IMPLIED	=> PERIM_NET
# DST_REMOTE		=> INTERNET_HOST

$fwopts{rules_file} =  "rules";

# Clear out directory
system( "rm -fr test-data/out/*" );

# Save current chains
system( "ipchains-save > saved-chains" ) == 0
  or die "couldn't save current chains: $?\n";

my @SRC	    = qw( ANY INT_IP INT_NET INT_REM_HOST      );
my @DST	    = qw( ANY PERIM_IP PERIM_NET INTERNET_HOST );
my @POLICY  = qw( accept account deny );
for my $pol ( @POLICY ) {
  for my $src ( @SRC ) {
    for my $dst ( @DST ) {
      my @MASQ;
    SWITCH:
      for ($pol) {
	/deny/  && do {
	  @MASQ = qw( nomasq );
	  last SWITCH;
	};
	/accept|account/ && do {
	  @MASQ = qw( masq nomasq );
	  last SWITCH;
	};
      }
      for my $masq ( @MASQ ) {
	open RULES, ">rules" 
	  or die "couldn't open rules file for writing: $!\n";
	print RULES "$pol telnet -src $src -dst $dst -$masq\n";
	close RULES;
	$fwctl = new Fwctl( %fwopts );
	$fwctl->configure;
	system( "ipchains -L -v -n |tail +25 |sed -e 's|(.*)||' > test-data/out/$pol-$src-$dst-$masq" ) == 0
	  or die "error dumping chains configuration: $?\n";
	my $result = system( "cmp", "-s", "test-data/out/$pol-$src-$dst-$masq",
			     "test-data/in/$pol-$src-$dst-$masq" );
	ok( $result, 0 );
	# Remote output of test that succeeds.
	unlink "test-data/out/$pol-$src-$dst-$masq"  if $result == 0;
      }
    }
  }

}

# Some of the other tests
my %SERVICE_TESTS = (
		     "accept-all-INT_NET-INTERNET-masq" => "accept all -src INT_NET  -dst INTERNET -masq",
		     "account-all-INT_NET-PERIM_NET"	=> "account all -src INT_NET -dst PERIM_NET",
		     "accept-dhcp-INT_NET-INT_IP"	=> "accept dhcp -src INT_NET -dst INT_IP",
		     "deny-dhcp-INT_NET"		=> "deny dhcp -src INT_NET -nolog",
		     "accept-ftp-INTERNET-PERIM_HOST"	=> "accept ftp -src INTERNET -dst PERIM_HOST",
		     "accept-ftp-PERIM_HOST-INTERNET-noport"	=>"accept ftp -src PERIM_HOST -dst INTERNET -noport",
		     "accept-http-INTERNET-PERIM_HOST"	=> "accept http -src INTERNET -dst PERIM_HOST",
		     "accept-http-PERIM_HOST-INTERNET-port"	=> "accept http -src PERIM_HOST -dst INTERNET -port 80,443,8000:9000",
		     "accept-name_service-INT_HOST-PERIM_HOST-query" => "accept name_service -src INT_HOST -dst PERIM_HOST -query 5353",
		     "accept-name_service-PERIM_HOST-INTERNET-server" => "accept name_service -src PERIM_HOST -dst INTERNET -server -query  5353",
		     "accept-name_service-INT_NET-INT_IP" => "accept name_service -src INT_NET -dst INT_IP",
		     "deny-netbios-INT_NET-nolog" => "deny netbios -src INT_NET -nolog",
		     "accept-ntp-PERIM_HOST-NTP_SERVERS" => "accept ntp -src PERIM_HOST -dst NTP_SERVERS",
		     "accept-ntp-PERIM_HOST-NTP_SERVERS-masq-client" => "accept ntp -src PERIM_HOST -dst NTP_SERVERS -client -masq",
		     "accept-ping-INT_NET-PERIM_NET"	=> "accept ping -src INT_NET -dst PERIM_NET",
		     "accept-ping-INT_NET-INTERNET-masq"	=> "accept ping -src INT_NET -dst INTERNET -masq",
		     "accept-rsh-PERIM_IP-PERIM_HOST" => "accept rsh -src PERIM_IP -dst PERIM_HOST",
		     "deny-snmp-INT_NET-nolog" =>  "deny snmp -src INT_NET -nolog",
		     "accept-timed-INT_NET-INT_IP" => "accept timed -src INT_NET -dst INT_IP",
		     "accept-traceroute-INT_NET-INTERNET-masq" => "accept traceroute -src INT_NET -dst INTERNET -masq",
		     "accept-traffic_control" => "accept traffic_control",
		     "accept-syslog-INT_HOST-INT_IP" => "accept syslog -src INT_HOST -dst INT_IP -client",
		     "accept-syslog-INTERNET_HOST-EXT_IP" => "accept syslog -src INTERNET_HOST -dst EXT_IP",
		     "accept-hylafax-INT_NET-INT_IP" => "accept hylafax -src INT_NET -dst INT_IP",
		    );

for my $name ( sort keys %SERVICE_TESTS) {
  my $rule = $SERVICE_TESTS{$name};
  open RULES, ">rules" 
    or die "couldn't open rules file for writing: $!\n";
  print RULES $rule, "\n";
  close RULES;
  $fwctl = new Fwctl( %fwopts );
  $fwctl->configure;
  system( "ipchains -L -v -n |tail +25 |sed -e 's|(.*)||' > test-data/out/$name" ) == 0
    or die "error dumping chains configuration: $?\n";
  my $result = system( "cmp", "-s", "test-data/out/$name", "test-data/in/$name" );
  ok( $result, 0 );
  # Remote output of test that succeeds.
  unlink "test-data/out/$name"  if $result == 0;
}

END {
  if (-e "saved-chains" ) {
    system ( "ipchains", "-F" );
    system ( "ipchains", "-X" );
    system( "ipchains-restore < saved-chains" ) == 0
      or die "failed to restore chains: $?\n";
    unlink "saved-chains";
  }
  unlink "rules";
}


1;



