Summary: Program to control the firewall with high level syntax
Name: Fwctl
Version: 0.21
Release: 1i
Source: http://iNDev.iNsu.COM/Fwctl/%{name}-%{version}.tar.gz
Copyright: GPL or Artistic License
Group: Development/Libraries/Perl
Prefix: /usr
URL: http://iNDev.iNsu.COM/Fwctl/
BuildRoot: /var/tmp/%{name}-%{version}
BuildArchitectures: noarch
Prereq: /sbin/chkconfig
Requires: perl Net-IPv4Addr

%description
Fwctl is a module to configure the Linux kernel packet filtering firewall
using higher level abstraction than rules on input, output and forward
chains. It supports masquerading and accounting as well.

%prep
%setup -q
# Update all path to the perl interpreter
find -type f -exec sh -c 'if head -c 100 $0 | grep -q "^#!.*perl"; then \
		perl -p -i -e "s|^#!.*perl|#!/usr/bin/perl|g" $0; fi' {} \;

%build
perl Makefile.PL 
make OPTIMIZE="$RPM_OPT_FLAGS"
#make test

%install
rm -fr $RPM_BUILD_ROOT
eval `perl '-V:installarchlib'`
mkdir -p $RPM_BUILD_ROOT/$installarchlib
make 	PREFIX=$RPM_BUILD_ROOT/usr \
	INSTALLMAN1DIR=$RPM_BUILD_ROOT/usr/man/man1 \
   	INSTALLMAN3DIR=$RPM_BUILD_ROOT/`dirname $installarchlib`/man/man3 \
   	pure_install

pod2man --section=8 --release=%{version} fwctl  > fwctl.8
mkdir -p $RPM_BUILD_ROOT/usr/man/man8
install -m644 fwctl.8 $RPM_BUILD_ROOT/usr/man/man8

umask 007
mkdir -p $RPM_BUILD_ROOT/{usr/sbin,etc/{fwctl,cron.hourly,rc.d/init.d,logrotate.d}}
install -m 750 fwctl $RPM_BUILD_ROOT/usr/sbin
install -m 750 fwctl.init $RPM_BUILD_ROOT/etc/rc.d/init.d/fwctl
install -m 750 fwctl.cron $RPM_BUILD_ROOT/etc/cron.hourly/fwctl_acct
install -m 750 fwctl.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/fwctl
install -m 640 etc/* $RPM_BUILD_ROOT/etc/fwctl

# Fix packing list
for packlist in `find $RPM_BUILD_ROOT -name '.packlist'`; do
	mv $packlist $packlist.old
	sed -e "s|$RPM_BUILD_ROOT||g" < $packlist.old > $packlist
	rm -f $packlist.old
done

# Make a file list
find $RPM_BUILD_ROOT -type d -path '*/usr/lib/perl5/site_perl/5.005/*' \
    -not -path '*/auto' -not -path "*/*-linux" | \
    sed -e "s!$RPM_BUILD_ROOT!%dir !" > %{name}-file-list
    
find $RPM_BUILD_ROOT/usr/lib/perl5 -type f -o -type l | \
	grep -v perllocal.pod | \
	sed -e "s|$RPM_BUILD_ROOT||g" >> %{name}-file-list

perl -n -i -e 'print "%doc " if m!man/man|\.pod!; print; ' %{name}-file-list

%post 
if [ "$1" = 1 ]; then
	chkconfig --add fwctl
fi

%preun 
if [ "$1" = 0 ]; then
	chkconfig --del fwctl
fi

%clean
rm -fr $RPM_BUILD_ROOT

%files -f %{name}-file-list
%defattr(-,root,root)
%doc README ChangeLog TODO
/usr/sbin/fwctl
/usr/man/man8/fwctl.8
%config /etc/rc.d/init.d/fwctl
%dir /etc/fwctl
%config(missingok) /etc/logrotate.d/fwctl
%config(noreplace) /etc/fwctl/aliases
%config(noreplace) /etc/fwctl/interfaces
%config(noreplace) /etc/fwctl/rules
%config /etc/cron.hourly/fwctl_acct

%changelog
* Tue Oct 19 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.21-1i]
- Updated to version 0.21.

* Wed Sep 15 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.20-1i]
- Updated to version 0.20.

* Fri Sep 03 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.18-1i]
- Updated to version 0.18.

* Mon Aug 23 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.16-1i]
- Fixed botched release.
 
* Mon Aug 23 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
- Updated to version 0.15.
- Added requirements for Network-IPv4Addr.

* Thu Aug 19 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
- Updated to version 0.14.
- Put in man page.

* Mon Jul 05 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.13-1i]
- Updated to version 0.13.

* Mon Jul 05 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.12-1i]
- Updated to version 0.12.

* Mon Jul 05 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.11-1i]
- Updated to version 0.11.

* Sat May 29 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.10-1i]
- First RPM release.

