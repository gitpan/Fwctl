#
#    lpd.pm: Fwctl service module to handle the Berkeley Line Printer protocol.
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
package Fwctl::Services::lpd;

use strict;

use Fwctl::RuleSet qw(:tcp_rulesets :masq);
use IPChains;

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  bless {}, $class;
}

sub prototypes {
  my ($self,$target,$options) = @_;

  # Check for printer service
  my $local_ports = $options->{local_port} || "512:1023";
  my $port	  = getservbyname "printer", 'tcp' || "515";
  # Build prototypes
  (
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 'tcp',
		 SourcePort => $local_ports,
		 DestPort   => $port,
		 %{$options->{ipchains}},
		),
  );
}

sub block_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;


  my ($lpd,$stderr) = $self->prototypes( $target, $options );
  block_tcp_ruleset( $lpd,	$src, $src_if, $dst, $dst_if );
}

sub accept_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($lpd,$stderr) = $self->prototypes( $target, $options );

  my $masq = defined $options->{portfw} ? PORTFW :
    $options->{masq} ? MASQ : NOMASQ;
  accept_tcp_ruleset( $lpd, $src, $src_if, $dst, $dst_if,
		      $masq, $options->{portfw} );
}

sub account_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($lpd,$stderr) = $self->prototypes( $target, $options );
  my $masq = defined $options->{portfw} ? PORTFW :
    $options->{masq} ? MASQ : NOMASQ;
  acct_tcp_ruleset( $lpd, $src, $src_if, $dst, $dst_if, $masq );
}

sub valid_options {
  my  $self = shift;
  ( "local_port=s" );
}

1;
=pod

=head1 NAME

Fwctl::Services::lpd - Fwctl module to handle the Berkeley Line Printer
		       protocol.

=head1 SYNOPSIS

    accept   lpd -src INTERNAL_NET -dst PRINTER

=head1 DESCRIPTION

The lpd modules handles the LP protocol. It permits a tcp connection from
the privileged 512 through 1023 to the printer port (515). You can use
the local_port option to specifies another range of port.

=head1 AUTHOR

Copyright (c) 1999,2000 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

