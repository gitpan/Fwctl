#
#    Report.pm - Module that compiles reports from the logs preprocessed by
#		 the fwctllog program.
#
#    This file is part of Fwctl.
#
#    Author: Francis J. Lacoste <francis@iNsu.COM>
#
#    Copyright (C) 1999 Francis J. Lacoste, iNsu Innovations Inc.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms same terms as perl itself.
#
package Fwctl::Report;

use strict;

use vars qw( $VERSION @EXPORT @EXPORT_OK %EXPORT_TAGS @ISA );

use Symbol;
use Time::Local;
use Exporter;

use vars qw( $DATE_MANIP );

=pod

=head1 NAME

Fwctl::Report - Generates reports from fwctllog output.

=head1 SYNOPSIS

    use Fwctl::Report;

    my $report = new Fwctl::Report( options ... );

    my $src_alias_sum = $report->src_alias_summary_report;

    foreach my $r ( @$src_alias_sum ) {
	print $r->{host_ip}, " = ", $r->{count}, "\n";
    }

=head1 DESCRIPTION

The Fwctl::Report(3) module can be used to generate various reports from
the output of the B<fwctllog> program.

This module generates two kinds of report C<summary> and <report>. The
summary compiles the number of occurence for an item (source,
destination, service, etc.). The report methods will returns all the
log entry that shares the same key ( source, destination, service,
etc.)

=cut

BEGIN {
    ($VERSION) = '$Revision: 1.3 $' =~ /(Revision: ([\d.]+))/;
    @ISA = qw( Exporter );

    @EXPORT = ();

    @EXPORT_OK = ();

    %EXPORT_TAGS = ( fields => [ qw(  TIME ACTION DEVICE IF CHAIN
				      PROTO PROTO_NAME
				      SRC_IP SRC_HOST SRC_IF
				      SRC_ALIAS SRC_PORT SRC_SERV
				      DST_IP DST_HOST DST_IF
				      DST_ALIAS DST_PORT DST_SERV
				    )
				],
		    );
}



BEGIN {
    $DATE_MANIP = 0;
    eval "use Date::Manip;";
    $DATE_MANIP = 1 unless $@;
}

BEGIN {
    # Create the necessary constant
    my $i = 0;
    for my $f ( @{$EXPORT_TAGS{fields}} ) {
	eval "use constant $f => $i;";
	$i++;
    }

    Exporter::export_ok_tags( 'fields' );
};

use constant SERVICE_ALIAS_KEY =>
  sub { if ( $_[0][PROTO] == 6 || $_[0][PROTO] == 17)
	{
	    return $_[0][DST_ALIAS] . "/" . $_[0][PROTO] . "/" .
	           $_[0][DST_PORT];
	} else {
	    return $_[0][DST_ALIAS] . "/" . $_[0][PROTO] . "/" .
		   $_[0][SRC_PORT] . "/" . $_[0][DST_PORT];
	}
    };

use constant SERVICE_HOST_KEY	    =>
sub { if ( $_[0][PROTO] == 6 || $_[0][PROTO] == 17 )
      {
	  return $_[0][DST_IP] . "/" . $_[0][PROTO] . "/" . $_[0][DST_PORT];
      } else {
	  return $_[0][DST_IP] .   "/" . $_[0][PROTO] . "/" .
	         $_[0][SRC_PORT] . "/" . $_[0][DST_PORT];
      }
  };

use constant SERVICE_KEY	    =>
  sub { if ( $_[0][PROTO] == 6 || $_[0][PROTO] == 17) {
	     return $_[0][PROTO] . "/" . $_[0][DST_PORT];
	} else {
	     return $_[0][PROTO] . "/" . $_[0][SRC_PORT]."/" . $_[0][DST_PORT];
	}
    };


use constant DST_HOST_KEY   => sub { $_[0][DST_IP] };

use constant DST_ALIAS_KEY  => sub { $_[0][DST_ALIAS] };

use constant SRC_HOST_KEY   => sub { $_[0][SRC_IP] };

use constant SRC_ALIAS_KEY  => sub { $_[0][SRC_ALIAS] };

use constant SRC_HOST_SUMMARY_RECORD =>
  sub { { host_ip    => $_[0][SRC_IP],
	  host_name  => $_[0][SRC_HOST],
	  host_alias => $_[0][SRC_ALIAS],
         };
    };

use constant SRC_ALIAS_SUMMARY_RECORD =>
  sub { {
	  host_alias => $_[0][SRC_ALIAS],
         };
    };

use constant DST_ALIAS_SUMMARY_RECORD =>
  sub { { 
	  host_alias => $_[0][DST_ALIAS], 
       };
    };

use constant DST_HOST_SUMMARY_RECORD =>
  sub { { host_ip    => $_[0][DST_IP],
	  host_name  => $_[0][DST_HOST],
	  host_alias => $_[0][DST_ALIAS],
         };
    };

use constant SERVICE_SUMMARY_RECORD =>
  sub {
      my $result = { proto      => $_[0][PROTO],
		     proto_name => $_[0][PROTO_NAME],
		     dst_port   => $_[0][DST_PORT],
		     dst_serv   => $_[0][DST_SERV],
		   };
      if ( $_[0][PROTO] != 6 && $_[0][PROTO] != 17 ) {
	  $result->{src_port} = $_[0][SRC_PORT];
	  $result->{src_serv} = $_[0][SRC_SERV];
      }
      $result;
  };

use constant SERVICE_ALIAS_SUMMARY_RECORD =>
  sub {
      my $result = { host_alias => $_[0][DST_ALIAS],
		     proto      => $_[0][PROTO],
		     proto_name => $_[0][PROTO_NAME],
		     dst_port   => $_[0][DST_PORT],
		     dst_serv   => $_[0][DST_SERV],
		   };
      if ( $_[0][PROTO] != 6 && $_[0][PROTO] != 17 ) {
	  $result->{src_port} = $_[0][SRC_PORT];
	  $result->{src_serv} = $_[0][SRC_SERV];
      }
      $result;
  };

use constant SERVICE_HOST_SUMMARY_RECORD =>
  sub {
      my $result = { host_ip    => $_[0][DST_IP],
		     host_name  => $_[0][DST_HOST],
		     host_alias => $_[0][DST_ALIAS],
		     proto	=> $_[0][PROTO],
		     proto_name => $_[0][PROTO_NAME],
		     dst_port   => $_[0][DST_PORT],
		     dst_serv   => $_[0][DST_SERV],
		   };
      if ( $_[0][PROTO] != 6 && $_[0][PROTO] != 17 ) {
	  $result->{src_port} = $_[0][SRC_PORT];
	  $result->{src_serv} = $_[0][SRC_SERV];
      }
      $result;
  };

sub summary_iterator {
    my ($records, $get_key_sub, $create_record_sub ) = @_;

    my %cache = ();
    foreach my $r ( @$records ) {
	my $key = $get_key_sub->( $r );
	if ( ! exists $cache{$key} ) {
	    $cache{$key} = $create_record_sub->( $r );
	    $cache{$key}{count} = 0;
	    $cache{$key}{first} = $r->[TIME];
	}
	$cache{$key}{count}++;
	$cache{$key}{last} = $r->[TIME];
    }

    return [ sort { $b->{count} <=> $a->{count} } values %cache ];
}

sub report_iterator {
    my ( $records,  $key_sub ) = @_;

    my %cache = ();
    foreach my $r ( @$records ) {
	my $key = $key_sub->( $r );

	unless ( exists $cache{$key}) {
	    $cache{$key} = [ $key, [] ];
	}
	push @{$cache{$key}[1]}, $r;
    }
    return [ map { $_->[1] } sort { $a->[0] cmp $b->[0] } values %cache ];
}

sub remove_duplicates {
    my ($records,$cutoff) = @_;

    # Sort by timestamp
    my @new_records = ();
    foreach my $r ( @$records ) {
	my $window = $r->[TIME] - $cutoff;
	my $seen = 0;
	for ( my $i = $#new_records;
	      $i >= 0 && $new_records[$i][TIME] > $window;
	      $i--
	    )
	{
	    my $nr = $new_records[$i];
	    next unless $r->[PROTO]  == $nr->[PROTO];
	    next unless $r->[SRC_IP] == $nr->[SRC_IP];
	    next unless $r->[DST_IP] == $nr->[DST_IP];
	    if ( $r->[PROTO] == 6 ||
		 $r->[PROTO] == 17
	       )
	    {
		# For TCP/UDP we only need to check the dst port
		next unless $r->[DST_PORT] == $nr->[DST_PORT];
	    } else {
		next unless $r->[SRC_PORT] == $nr->[SRC_PORT];
		next unless $r->[DST_PORT] == $nr->[DST_PORT];
	    }

	    # This is part of the same try
	    $seen = 1;
	    last;
	}
	push @new_records, $r unless $seen;
    }

    return \@new_records;
}

sub parse_date {
    my $str = shift;

    if ( $DATE_MANIP) {
	my $date = ParseDate( $str ) or return undef;
	return UnixDate( $date, '%s' );
    } else {
	my ( $yearpart, $year, $month, $day, $time, $hour, $min, $sec) =
	  $str =~ /((\d\d\d?\d?|\d\d)?-?(\d\d?)-(\d\d?) ?)?((\d\d?):(\d\d?):?(\d\d?)?)?/;
	return undef unless $yearpart ||  $time;

	if ( $yearpart ) {
	    if (defined $year) {
		$year = $year > 1900 ? $year - 1900 :
				       $year < 70 ? $year + 100 : $year;
	    } else {
		$year = (localtime)[5];
	    }
	    $month = $month == 12 ? 0 : $month - 1;
	} else {
	    ($year,$month,$day ) = (localtime)[5,4,3];
	}
	unless ($time) {
	    # Midnight
	    ($hour,$min,$sec) = (0,0,0);
	}
	$sec ||= 0;
	return timelocal $sec, $min, $hour, $day, $month, $year;
    }
}

sub parse_period {
    my $str = shift;
    if ( $DATE_MANIP ) {
	my $period = ParseDateDelta( $str ) or return undef;
	return Delta_Format( $period, 0, '%st' );
    } else {
	my ( $weeks, $days, $hours, $mins, $secs ) =
	  $str =~ /(?:(\d+) ?w[eks ]*)?(?:(\d+) ?d[ays ]*)?(?:(\d+) ?h[hours ]*)?(?:(\d+) ?m[inutes ]*)?(?:(\d+) ?s[econds ]*)?/i;

	my $time = 0;

	$time += $weeks * 7  * 24 * 60 * 60 if $weeks;
	$time += $days  * 24 * 60 * 60	    if $days;
	$time += $hours * 60 * 60	    if $hours;
	$time += $mins  * 60		    if $mins;
	$time += $secs			    if $secs;

	return $time || undef;
    }
}

sub check_constraint {
    my ( $test, $match) = @_;

    return 1 unless defined $match && @$match;

    foreach my $m ( @$match ) {
	return 1 if lc $test eq lc $m;
    }
    return 0;
}

sub read_records {
    my $self = shift;

    # Read in the data
    my $records = [];
    push @{$self->{opts}{files}}, \*STDIN unless @{$self->{opts}{files}};
  FILE:
    foreach my $file ( @{$self->{opts}{files}} ) {
	my $fh;
	if ( ref $file ) {
	    $fh = $file;
	} elsif ( $file eq "-" ) {
	    $fh = \*STDIN;
	} else {
	    $fh = gensym;
	    open $fh, $file
	      or do { warn "can't open file $file\n"; next FILE };
	}

	while (<$fh>) {
	    chomp;
	    my @fields = split /\|/, $_;
	    if ( ! defined $self->{start}) {
		$self->{start} = $fields[TIME];
		$self->{end} = $self->{start} + $self->{period}
		  if defined $self->{period};
	    }
	    # Skip fields outside the period
	    next unless $self->{start} <= $fields[TIME] &&
	      $self->{end} >= $fields[TIME];

	    next unless check_constraint( $fields[SRC_IP],
					  $self->{opts}{src} ) ||
			check_constraint( $fields[SRC_HOST],
					  $self->{opts}{src} );
	    next unless check_constraint( $fields[DST_IP],
					  $self->{opts}{dst} ) ||
			check_constraint( $fields[DST_HOST],
					  $self->{opts}{dst} );
	    next unless check_constraint( $fields[SRC_ALIAS],
					  $self->{opts}{salias} );
	    next unless check_constraint( $fields[DST_ALIAS],
					  $self->{opts}{dalias} );
	    next unless check_constraint( $fields[DST_PORT],
					  $self->{opts}{port} ) ||
			check_constraint( $fields[DST_SERV],
					  $self->{opts}{port} );
	    next unless check_constraint( $fields[PROTO],
					  $self->{opts}{proto} ) ||
			check_constraint( $fields[PROTO_NAME],
					  $self->{opts}{proto} );

	    push @$records, \@fields;
	}
    }

    # Records are sorted by time.
    $self->{records} = [ sort { $a->[TIME] <=> $b->[TIME] } @$records ];

    # Removes packet logs that are in the same window
    if ( $self->{threshold} > 0 ) {
	$self->{records} = remove_duplicates( $self->{records},
					      $self->{threshold} );
    }
}


=pod

=head1 CREATING A NEW REPORT OBJECT

    Ex. my $report = new Fwctl::Report( start  => 'yesterday',
					period => '1 day',
					files  => [ 'log' ] );

=head2 PARAMETERS

The C<new> method accepts the following parameter :

=over

=item files

Specifies the file from which to read the F<fwctllog> output. It is an
array of file handle or file names. If this parameter is not specified
the records will be read from STDIN.

=item start

Sets the start of the report's period. If the Date::Manip(3) module is
installed, you can use any format that this module can parse. If that module
is'nt installed you must use the following format YYYY-MM-DD HH:MM:SS or any
meaningful subset of that format.

If this option is not used, the report will start with the first record.

=item end

Sets the end of the report's period. If the Date::Manip(3) module is
installed, you can use any format that this module can parse. If that module
is'nt installed you must use the following format YYYY-MM-DD HH:MM:SS or any
meaningful subset of that format.

If this option is not used, the report will end with the last record.

=item period

Sets the length of the report's period. This length is interpreted relative
to the report's start. This option has priority over the B<end> option.

If you have the Date::Manip module installed, you can use any format that this
module can parse. If that module isn't available, you can use a subset of the
following format X weeks X days X hours X mins X secs.

=item threshold

This option will removed records identical in protocol, destination
ports, source addresses and destination addressesses that appears in
the time window specified by the threshold parameters. Defaults is 120
(2 minutes). Use 0 to generates reports for all the packets.

=item src

Restrict records to those whose source address matches B<src>.
You can use hostname or IP address.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item dst

Restrict records to those whose destination address matches B<dst>.
You can use hostname or IP address.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item salias

Restrict records to those whose source alias matches B<salias>. You can use
any alias as specified in the I<aliases> configuration file.


You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item dalias

Restrict records to those whose destination alias matches B<dalias>.
You can use any alias as specified in the I<aliases> configuration file.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item sif

Restrict records to those whose source address is on the interface B<sif>.
You can use any interface as specified in the I<interfaces>
configuration file.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item dif

Restrict records to those whose destination address is on the interface B<dif>.
You can use any interface as specified in the I<interfaces>
configuration file.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item proto

Restrict records to those whose protocol matches B<proto>.
You can use protocol name or number.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=item port

Restrict records to those whose destination port matches B<port>.
You can use service name or number.

You can use this parameter multiple times to specify multiple
possibility. The record will be included if it matches any of those.

=back

=cut

sub new {
    my $proto = shift;
    my $class = ref $proto || $proto;

    my $self = { opts	    => { @_ },
		 records    => undef,
		 start	    => undef,
		 end	    => undef,
		 period	    => undef,
		 threshold  => undef,
	       };

    # Determine start and end of the report;
    if ( $self->{opts}{start} ) {
	$self->{start} = Fwctl::Report::parse_date( $self->{opts}{start} ) 
	  or die "invalid start date format: $self->{opts}{start}\n";
    }

    if ( $self->{opts}{period} ) {
	$self->{period} = Fwctl::Report::parse_period( $self->{opts}{period}) 
	  or die "fwctlreport: invalid period delta: $self->{opts}{period}\n";
	if (  $self->{start} ) {
	    $self->{end} = $self->{start} + $self->{period};
	}
    } elsif ( $self->{opts}{end} ) {
	$self->{end} = Fwctl::Report::parse_date( $self->{opts}{end} ) 
	  or die "fwctlreport: invalid end date format: $self->{opts}{end}\n";
    } else {
	$self->{end} = time;
    }

    if ( $self->{opts}{threshold} ) {
	$self->{threshold} = Fwctl::Report::parse_period( $self->{opts}{threshold} )
	  or die "fwctlreport: invalid threshold: $self->{opts}{threshold}\n";
    } else {
	$self->{threshold} = 120; # 2 minutes
    }

    bless $self, $class;

    $self->read_records;

    $self;
}

=pod

=head1 METHODS

=head1 start()

Return the start of the report in seconds since epoch.

=cut

sub start {
    $_[0]->{start};
}

=pod

=head1 end()

Returns the end of the report in seconds since epoch.

=cut

sub end {
    $_[0]->{end};
}

=pod

=head1 period()

Returns the length of the report's period ( $report->end() - $report->start() )

=cut

sub period {
    $_[0]->{end} - $_[0]->{period};
}

=pod

=head1 records()

Returns an array reference to all the records read and which makes the
report's sample.

=head2 RECORD FIELDS

Each record is an array ref. You can accessed the individual fields of
the record by using the following constants. (Those can be imported by
using the C<:fields> import tag.)

=over

=item TIME

The epoch time of the log entry.

=item ACTION

The resulting action (ACCEPT,DENY,REJECT).

=item DEVICE

The physical device on which the packet was logged.

=item IF

The Fwctl(3) interface to which this device is related.

=item CHAIN

The kernel chain on which that packet was logged.

=item PROTO

The protocol number.

=item PROTO_NAME

The name of the protocol.

=item SRC_IP

The source address of the packet.

=item SRC_HOST

The source hostname.

=item SRC_IF

The Fwct(3) interface related to the source address.

=item SRC_ALIAS

The Fwctl(3) alias associated to the source address.

=item SRC_PORT

The source port of the logged packet.

=item SRC_SERV

The service name associated to the logged packet.

=item DST_IP

The destination IP of the packet.

=item DST_HOST

The destination hostname.

=item DST_IF

The Fwctl(3) interface associated with the destination address.

=item DST_ALIAS

The Fwctl(3) alias related to the destination address.

=item DST_PORT

The destination port number.

=item DST_SERV

The service name of the the destination port.

=back

=cut

sub records {
    # Copy the records
    [ @{$_[0]->{records}} ];
}

=pod

=head1 REPORTS

The following report generation methods are available :

=head2 service_summary_report()

    my $r = $report->service_summary_report();


Generates a report that shows the number of log entries for each
services. 

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item proto 

The protocol number.

=item proto_name

The protocol name.

=item dst_port

The destination port.

=item dst_serv

The destination service's name.

=item src_port

If the protocol B<is not> UDP or TCP, the source port.

=item src_serv

If the protocol B<is not> UDP or TCP, the service name associated to the 
source port.

=item count

The number of log entries matching the service.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub service_summary_report {
    return summary_iterator( $_[0]->{records}, SERVICE_KEY,
			     SERVICE_SUMMARY_RECORD );
}

=pod

=head2 service_report()

    my $r = $report->service_report();

Generates a report that sort the log entries by service.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same service.

=cut

sub service_report {
    return report_iterator( $_[0]->{records}, SERVICE_KEY );
}

=pod

=head2 service_alias_summary_report()

    my $r = $report->service_alias_summary_report();


Generates a report that shows the number of log entries for each
destination aliases / service.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item proto

The protocol number.

=item proto_name

The protocol name.

=item host_alias

The alias of the destination hosts.

=item dst_port

The destination port.

=item dst_serv

The destination's service name.

=item src_port

If the protocol B<is not> UDP or TCP, the source port.

=item src_serv

If the protocol B<is not> UDP or TCP, the service name associated to the 
source port.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub service_alias_summary_report {
    return summary_iterator( $_[0]->{records}, SERVICE_ALIAS_KEY,
			     SERVICE_ALIAS_SUMMARY_RECORD );
}

=head2 service_alias_report()

    my $r = $report->service_alias_report();

Generates a report that sort the log entries by destination alias and
service.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same destination alias and service.

=cut

sub service_alias_report {
    return report_iterator( $_[0]->{records}, SERVICE_ALIAS_KEY );
}

=pod

=head2 service_host_summary_report()

    my $r = $report->service_host_summary_report();


Generates a report that shows the number of log entries for each
destination aliases / service.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item proto

The protocol number.

=item proto_name

The protocol name.

=item host_ip

The destination host ip address.

=item host_name

The destination host name.

=item host_alias

The alias of that host.

=item dst_port

The destination port.

=item dst_serv

The destination service's name.

=item src_port

If the protocol B<is not> UDP or TCP, the source port.

=item src_serv

If the protocol B<is not> UDP or TCP, the service name associated to the 
source port.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub service_host_summary_report {
    return summary_iterator( $_[0]->{records}, SERVICE_HOST_KEY,
			     SERVICE_HOST_SUMMARY_RECORD );

}

=head2 service_host_report()

    my $r = $report->service_host_report();

Generates a report that sort the log entries by destination host and
service.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same destination host and service.

=cut

sub service_host_report {
    return report_iterator( $_[0]->{records}, SERVICE_HOST_KEY );
}

=pod

=head2 src_alias_summary_report()

    my $r = $report->service_alias_summary_report();


Generates a report that shows the number of log entries for each
source aliases.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item host_alias

The source alias.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub src_alias_summary_report {
    return summary_iterator( $_[0]->{records}, SRC_ALIAS_KEY, 
			     SRC_ALIAS_SUMMARY_RECORD );
}

=head2 src_alias_report()

    my $r = $report->src_alias_report();

Generates a report that sort the log entries by source alias.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same source alias.

=cut

sub src_alias_report {
    return report_iterator( $_[0]->{records}, SRC_ALIAS_KEY );
}

=pod

=head2 src_host_summary_report()

    my $r = $report->src_host_summary_report();


Generates a report that shows the number of log entries for each
source host.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item host_ip

The source host ip address.

=item host_name

The source host name.

=item host_alias

The alias of the source host.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub src_host_summary_report {
    return summary_iterator( $_[0]->{records}, SRC_HOST_KEY, 
			     SRC_HOST_SUMMARY_RECORD );

}

=head2 src_host_report()

    my $r = $report->src_host_report();

Generates a report that sort the log entries by source host.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same source host.

=cut

sub src_host_report {
    return report_iterator( $_[0]->{records}, SRC_HOST_KEY );
}

=pod

=head2 dst_alias_summary_report()

    my $r = $report->dst_alias_summary_report();


Generates a report that shows the number of log entries for each
destination aliases.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item host_alias

The destination alias.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub dst_alias_summary_report {
    return summary_iterator( $_[0]->{records}, DST_ALIAS_KEY, 
			     DST_ALIAS_SUMMARY_RECORD );
}

=head2 dst_alias_report()

    my $r = $report->dst_alias_report();

Generates a report that sort the log entries by destination alias.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same destination alias.

=cut

sub dst_alias_report {
    return report_iterator( $_[0]->{records}, DST_ALIAS_KEY );
}

=pod

=head2 src_host_summary_report()

    my $r = $report->src_host_summary_report();


Generates a report that shows the number of log entries for each
destination hosts.

The resulting report is an array ref of hash reference. Each report
record's has the following fields.

=over

=item host_ip

The destination host ip address.

=item host_name

The destination host name.

=item host_alias

The alias of the destination hosts.

=item count

The number of log entries.

=item first

The epoch time of the first occurence.

=item last

The epoch time of the last occurence.

=back

=cut

sub dst_host_summary_report {
    return summary_iterator( $_[0]->{records}, DST_HOST_KEY, 
			     DST_HOST_SUMMARY_RECORD );

}

=head2 dst_host_report()

    my $r = $report->dst_host_report();

Generates a report that sort the log entries by destination host.

The report is an array of arrays. Each elements of the report is an
array of records which shares the same destination host.

=cut

sub dst_host_report {
    return report_iterator( $_[0]->{records}, DST_HOST_KEY );
}

1;

__END__

=pod

=head1 AUTHOR

Copyright (c) 2000 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

Fwctl(3) Fwctl::RuleSet(3) fwctl(8) fwctllog(8) Fwctl::Report(3)
Date::Manip(3).

=cut

