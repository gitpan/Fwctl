#
#    all.pm: Fwctl service module that represents rules matching all IP traffic.
#
#    This file is part of Fwctl.
#
#    Author: Francis J. Lacoste <francis@iNsu.COM>
#
#    Copyright (C) 1999 Francis J. Lacoste, iNsu Innovations Inc.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms same terms as perl itself.
package Fwctl::Services::all;

use strict;

use Fwctl::RuleSet qw(:ip_rulesets :masq);
use IPChains;

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  bless {}, $class;
}

sub prototypes {
  my ($self,$target,$options) = @_;
  (
   IPChains->new(
		 Rule	    => $target,
		 %{$options->{ipchains}},
		),
  );
}

sub block_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  # Build prototype rule
  my ($fw) = $self->prototypes( $target, $options );

  block_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if );
  block_ip_ruleset( $fw, $dst, $dst_if, $src, $src_if  );
}

sub accept_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  # Build prototype rule
  my ($fw) = $self->prototypes( $target, $options );

  accept_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if,
		     $options->{masq} ? MASQ : NOMASQ
		   );
  accept_ip_ruleset( $fw, $dst, $dst_if, $src, $src_if, 
		     $options->{masq} ? UNMASQ : NOMASQ
		   );
}

sub account_rules {
  my $self = shift;
  my ( $target, $src, $src_if, $dst, $dst_if, $options ) = @_;

  # Build prototype rule
  my ($fw) = $self->prototypes( $target, $options );

  acct_ip_ruleset( $fw, $src, $src_if, $dst, $dst_if,
		   $options->{masq} ? MASQ : NOMASQ
		 );
  acct_ip_ruleset( $fw, $dst, $dst_if, $src, $src_if, 
		   $options->{masq} ? UNMASQ : NOMASQ
		 );

}

sub valid_options {
  (); # No options
}

1;
=pod

=head1 NAME

Fwctl::Services::all - Fwctl module to handle any IP traffic.

=head1 SYNOPSIS

    accept   all -src INTERNAL_NET -dst INTERNET -masq
    deny    all -src BAD_GUYS_NET	--account
    account all -src PERIM_NET -dst INTERNET

=head1 DESCRIPTION

The all module is used to match any IP traffic. It can be used for
accounting all traffic between nets or to create bazooka sized hole
in our filters.

Needless to say that

    accept   all

is not a really secure use of this module.

=head1 CAVEATS

The way Fwctl organizes its rules, the all rules will always be
processed after more specific rules. That is to say that if you 
use

    accept   all -src INTERNAL_NET
    block   ftp

This will result (perhaps unintuitively) in ftp being blocked also for
the INTERNAL_NET. This is becaus Fwctl optimizes its rules according
to protocol. So it processes rules for ICMP, TCP, UDP, OTHER and than ALL.
(Other is if you specify another protocol, but not any). This optimization
has only effects on rules matching without a protocol specified.

To fix the previous problem use :

    accept all -src INTERNAL_NET
    accept ftp -src INTERNAL_NET # Optimization work around
    block ftp

=head1 AUTHOR

Copyright (c) 1999 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

