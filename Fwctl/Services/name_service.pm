#
#    name_service.pm: Fwctl service module to handle the DNS protocol.
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
package Fwctl::Services::name_service;

use strict;

use Fwctl::RuleSet qw(:tcp_rulesets :udp_rulesets :masq :ports);
use IPChains;

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  bless {
	 query_port => UNPRIVILEGED_PORTS,
	}, $class;
}

sub prototypes {
  my ($self,$target,$options) = @_;

  # Build prototype rule
  (
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 'udp',
		 DestPort   => 'domain',
		 %{$options->{ipchains}},
		),
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 'tcp',
		 SourcePort => UNPRIVILEGED_PORTS,
		 DestPort   => 'domain',
		 %{$options->{ipchains}},
		),
  );
}

sub block_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($udp,$tcp) = $self->prototypes( $target, $options );

  if ($options->{server}) {
    $udp->attribute( SourcePort => 'domain' );
    block_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if );
  }
  my $query = $options->{"query-port"} || $self->{query_port};
  $udp->attribute( SourcePort => $query );
  block_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if );
  block_tcp_ruleset( $tcp, $src, $src_if, $dst, $dst_if );
}

sub accept_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($udp,$tcp) = $self->prototypes( $target, $options );
  if ($options->{server}) {
    $udp->attribute( SourcePort => 'domain' );
    accept_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if,
			$options->{masq} ? MASQ : NOMASQ
		      );
  }
  my $query = $options->{"query-port"} || $self->{query_port};
  $udp->attribute( SourcePort => $query );
  accept_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  accept_tcp_ruleset( $tcp, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
}

sub account_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($udp,$tcp) = $self->prototypes( $target, $options );
  if ($options->{server}) {
    $udp->attribute( SourcePort => 'domain' );
    acct_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if,
		      $options->{masq} ? MASQ : NOMASQ
		    );
  }
  my $query = $options->{"query-port"} || $self->{query_port};
  $udp->attribute( SourcePort => $query );
  acct_udp_ruleset( $udp, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  acct_tcp_ruleset( $tcp, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
}

sub valid_options {
  my  $self = shift;
  ( "query-port=s", "server" );
}

1;
=pod

=head1 NAME

Fwctl::Services::name_service - Fwctl module to handle the DNS protocol.

=head1 SYNOPSIS

    accept   name_service -src INTERNET -dst NAME_SERVER -server
    accept   name_service -src NAME_SERVER -dst INTERNET -query-port 5353

=head1 DESCRIPTION

The name_service module handles the DNS protocol. It can handle both
name server and resolver configuration. When using the I<server> option,
the query can be from the port 53 (for bind 4 compatibility) and above 1024.
You can use the I<query-port> option to specify the client port.

Default is to use only ports > 1024 as client port. (Usual resolver situation.)

=head1 AUTHOR

Copyright (c) 1999 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

