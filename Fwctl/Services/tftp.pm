#
#    timed.pm: Fwctl service module to handle the tftp protocol.
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
package Fwtcl::Services::tftp;

use strict;

use vars qw(@ISA);

BEGIN {
  require Exporter;

  @ISA = qw( Fwctl::Services::udp_service);

}

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self  = $class->SUPER::new(@_);
  $self->{port} = "tftp";
  bless $self,$class;
}

1;
=pod

=head1 NAME

Fwctl::Services::all - Fwctl module to handle tftp protocol.

=head1 SYNOPSIS

    deny   tftp 

=head1 DESCRIPTION

Service module to handle tftp protocol.

=head1 SEE ALSO

fwctl(8) Fwctl(3) Fwctl::RuleSet(3)

=cut

