#
#    hylafax.pm: Fwctl service module to handle the hylafax protocol.
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
package Fwctl::Services::ftp;

use strict;

use vars qw( @ISA );

use Carp;
@ISA = qw( Fwctl::Services::hylafax );

sub new {
  my $proto = shift;
  my $class = ref $proto || $proto;
  my $ctrl = getservbyname( "hylafax", "tcp");
  $ctrl ||= 4559;
  my $data = $ctrl - 1 ;
  bless { pasv_ports	=> UNPRIVILEGED_PORTS,
	  pasv		=> 1,
	  port		=> 1,
	  data_port	=> $data,
	  ctrl_port	=> $ctrl,
	}, $class;
}

sub valid_options {
  my  $self = shift;
  ();
}

1;
=pod

=head1 NAME

Fwctl::Services::hylafax - Fwctl module to handle the HylaFax protocol.

=head1 SYNOPSIS

    accept   hylafax -src INTERNAL_NET -dst INT_IP

=head1 DESCRIPTION

The hylafax module is used to handle the HylaFAX protocol which is
a variant of the FTP protocol.

=head1 OPTIONS

No service specific options.

=head1 AUTHOR

Copyright (c) 1999 Francis J. Lacoste and iNsu Innovations Inc.
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms as perl itself.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

