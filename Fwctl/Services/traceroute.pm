#
#    traceroute.pm: Fwctl service module to handle traceroute service.
#
#    This file is part of Fwctl.
#
#    Author: Francis J. Lacoste <francis@iNsu.COM>
#
#    Copyright (c) 1999,2000 Francis J. Lacoste, iNsu Innovations Inc.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms same terms as perl itself.
#
package Fwctl::Services::traceroute;

use strict;

use Fwctl::RuleSet qw(:ip_rulesets :masq :ports);
use IPChains;

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  bless {
	 port => "33434:33534",	# Default numer of hops is 30
	}, $class;
}

sub prototypes {
  my ($self,$target,$options) = @_;

  my $port = $options->{port} || $self->{port};

  # Build prototype rule
  (
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 'udp',
		 SourcePort => UNPRIVILEGED_PORTS,
		 DestPort   => $port,
		 %{$options->{ipchains}},
		),
  );
}

sub block_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;


  my ($fw) = $self->prototypes( $target, $options );
  block_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if );
}

sub accept_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($fw) = $self->prototypes( $target, $options );

  accept_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
}

sub account_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($fw) = $self->prototypes( $target, $options );

  acct_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if,
		    $options->{masq} ? MASQ : NOMASQ
		  );
}

sub valid_options {
  my  $self = shift;
  ( "port=s" );
}

1;
=pod

=head1 NAME

Fwctl::Services::traceroute - Fwctl module to handle traceroute service.

=head1 SYNOPSIS

    accept   traceroute -src INTERNAL_NET -dst INTERNET -masq
    deny    traceroute -src INTERNET	--account
    account traceroute -src INTERNET -dst PERIM_NET

=head1 DESCRIPTION

This module handle the usual UDP traffic used by the B<traceroute> program.
You can use the I<port> option to set the range of port used if your
program isn't using the default 33434 and higher.

=head1 AUTHOR

Copyright (c) 1999,2000 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

