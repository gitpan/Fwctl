#
#    pptp.pm: Fwctl service module to handle the PPTP service.
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
package Fwctl::Services::pptp;

use strict;

use Fwctl::RuleSet qw(:tcp_rulesets :ip_rulesets :masq :ports);
use IPChains;
use Carp;

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  bless {}, $class;
}

sub prototypes {
  my ($self,$target,$options) = @_;

  # Build prototype rule
  (
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 'tcp',
		 SourcePort => UNPRIVILEGED_PORTS,
		 DestPort   => 1723,
		 %{$options->{ipchains}},
		),
   IPChains->new(
		 Rule	    => $target,
		 Prot	    => 47, # GRE
		 %{$options->{ipchains}},
		),
  );
}

sub block_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($control,$gre) = $self->prototypes( $target, $options );

  block_tcp_ruleset( $control, $src, $src_if, $dst, $dst_if );
  block_ip_ruleset( $gre, $src, $src_if, $dst, $dst_if );
  block_ip_ruleset( $gre, $dst, $dst_if, $src, $src_if );
}

sub accept_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ($control, $gre ) = $self->prototypes( $target, $options );

  accept_tcp_ruleset( $control, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  accept_ip_ruleset( $gre, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  accept_ip_ruleset( $gre, $dst, $dst_if, $src, $src_if,
		     $options->{masq} ? UNMASQ : NOMASQ
		   );

  if ($options->{masq}) {
      system ( "/sbin/modprobe", "ip_masq_pptp" ) == 0
	or carp __PACKAGE__, ": couldn't load ip_masq_pptp: $?\n";
  }
}

sub account_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  my ( $control, $gre ) = $self->prototypes( $target, $options );

  acct_tcp_ruleset( $control, $src, $src_if, $dst, $dst_if,
		    $options->{masq} ? MASQ : NOMASQ
		  );
  acct_ip_ruleset( $gre, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  acct_ip_ruleset( $gre, $dst, $dst_if, $src, $src_if,
		   $options->{masq} ? UNMASQ : NOMASQ
		 );

}

sub valid_options {
  my  $self = shift;
  ( );
}

1;
=pod

=head1 NAME

Fwctl::Services::pptp - Fwctl module to handle the PPTP service.

=head1 SYNOPSIS

    accept pptp -src INT_NET -dst REMOTE_PPTP --masq

=head1 DESCRIPTION

This module will implements the rules to accept/block/account the PPTP
tunnelling protocol. In order to be able to masquerade that protocol, you
will need a kernel with the generic protocol masquerade patch applied.

See ftp://ftp.rubyriver.com/pub/jhardin/masquerade/ for informations.

=head1 AUTHOR

Copyright (c) 1999 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

