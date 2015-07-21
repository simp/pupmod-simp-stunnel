Summary: Stunnel Puppet Module
Name: pupmod-stunnel
Version: 4.2.0
Release: 9
License: Apache License, Version 2.0
Group: Applications/System
Source: %{name}-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: pupmod-concat >= 4.0.0-0
Requires: pupmod-iptables >= 2.0.0-0
Requires: pupmod-pki >= 3.0.0-0
Requires: pupmod-openldap >= 2.0.0-0
Requires: pupmod-common >= 4.1.0-4
Requires: puppet >= 3.3.0
Buildarch: noarch
Requires: simp-bootstrap >= 4.2.0
Obsoletes: pupmod-stunnel-test

Prefix: /etc/puppet/environments/simp/modules

%description
This Puppet module provides the capability to configure stunnel channels on your
system.

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/stunnel

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/stunnel
done

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/stunnel

%files
%defattr(0640,root,puppet,0750)
%{prefix}/stunnel

%post
#!/bin/sh

if [ -d %{prefix}/stunnel/plugins ]; then
  /bin/mv %{prefix}/stunnel/plugins %{prefix}/stunnel/plugins.bak
fi

%postun
# Post uninstall stuff

%changelog
* Wed Jul 21 2015 Nick Markowski <nmarkowski@keywcorp.com> - 4.2.0-9
- Moved stunnel's default pid location back to /var/run/stunnel/stunnel.pid.
- Stunnel's init script now only creates and chowns the pid file directory
  if it does not exist.

* Wed Jul 01 2015 Nick Markowski <nmarkowski@keywcorp.com> - 4.2.0-8
- Stunnel's default pid file location moved from /var/run/stunnel/stunnel.pid
  to /var/run/stunnel.pid

* Thu Apr 02 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-7
- Fixed a scoping error in the template

* Fri Feb 27 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-6
- Fixed a non-scoped call to @options in the stunnel ERB file.

* Thu Feb 19 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-5
- Migrated to the new 'simp' environment.

* Fri Jan 16 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-4
- Changed puppet-server requirement to puppet

* Thu Nov 06 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-3
- Fix chroot detection in SELinux mode.

* Tue Nov 04 2014 Trevor Vaughan <tvaughan@onxypoint.com> - 4.2.0-2
- Ensure that renegotiation and reset only apply on RHEL>6 systems.

* Sun Nov 02 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-1
- Updated to add the FIPS global option to the stunnel configuration.

* Tue Oct 21 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.0-0
- CVE-2014-3566: Updated protocols to mitigate POODLE.
- Updated all of the stunnel module to properly handle both RHEL6 and
  RHEL7.
- Now support multiple connect options.
- The connect/accept hosts and ports are no longer separate.

* Fri Aug 08 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-4
- Change 'delay' to 'no' by default to ensure that DNS lookups happen
  before entering the chroot jail. This currently does not work in
  RHEL7.
- Add nsswitch.conf to the chroot jail.

* Fri Aug 08 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-4
- Move stunnel outside of a chroot jail when SELinux is set to enforcing.

* Fri Apr 04 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-3
- Now simply include 'stunnel' in 'stunnel::add' instead of raising an
  exception.

* Wed Mar 26 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-2
- Moved stunnel::stunnel_add to stunnel::add
- Replaced all of the PKI copy code with a call to the new pki::copy define.
- Fixed a bug with the CA path and CRL path in the stunnel configuration file.

* Wed Mar 12 2014 Nick Markowski <nmarkowski@keywcorp.com> - 4.1.0-1
- Updated module for hiera/puppet3, and lint tests.
- Copied pki keys and certs to <chroot_path>/etc/stunnel/pki
- Added rspec tests.

* Tue Jan 28 2014 Kendall Moore <kmoore@keywcorp.com> 4.1.0-0
- Update to remove warnings about IPTables not being detected. This is a
  nuisance when allowing other applications to manage iptables legitimately.

* Mon Oct 07 2013 Kendall Moore <kmoore@keywcorp.com> - 4.0.0-12
- Updated all erb templates to properly scope variables.

* Fri Jun 07 2013 Kendall Moore <kmoore@keywcorp.com>
4.0.0-11
- Updated the stunnel start script to allow for the occurence of both *pid*
  and *chroot* to appear in a hostname

* Mon Jan 07 2013 Maintenance
4.0.0-10
- Created a test to install and configure stunnel and to make sure that the
  stunnel service is running.
- Created a test to add an stunnel on the first open port start at number 1024
  and ensure that the chosen port is in state LISTEN and owned by stunnel.

* Tue Nov 27 2012 Maintenance
4.0.0-9
- Fixed the stunnel init script to have proper startup output.
- Updated to set the umask for stunnel open files to 1048576 for heavily loaded
  systems.
- Updated the stunnel init script to allow unlimited processes since there is
  one per connection.

* Mon Nov 05 2012 Maintenance
4.0.0-8
- Removed the useless CRL copy exec.
- Removed the PKI Cert copy exec and replaced it with a recursive copy/purge
  file resource.

* Fri Sep 28 2012 Maintenance
4.0.0-7
- Moved the chroot run directory for stunnel from /var/run/stunnel to
  /var/stunnel since /var/run gets cleaned out upon reboot.

* Fri Aug 10 2012 Maintenance
4.0.0-6
- Update to set max open files ulimit to unlimited in the init script.

* Wed Apr 11 2012 Maintenance
4.0.0-5
- Moved mit-tests to /usr/share/simp...
- Updated pp files to better meet Puppet's recommended style guide.

* Fri Mar 02 2012 Maintenance
4.0.0-4
- Improved test stubs.

* Mon Dec 26 2011 Maintenance
4.0-3
- Updated the spec file to not require a separate file list.
- Scoped all of the top level variables.

* Tue Oct 25 2011 Maintenance
4.0-2
- Added a note about the transparent mode of stunnel not working
  properly in RHEL6.

* Mon Oct 10 2011 Maintenance
4.0-1
- Updated to put quotes around everything that need it in a comparison
  statement so that puppet > 2.5 doesn't explode with an undef error.

* Tue Jul 12 2011 Maintenance
4.0-0
- Stunnel doesn't care if we're using LDAP or not, so don't check for the
  value when setting up key permissions.

* Mon Apr 18 2011 Maintenance - 2.0.0-1
- Changed puppet://$puppet_server/ to puppet:///
- Ensure that stunnel does not restart when 'resolv.conf' or 'hosts' is updated.
- Ensure that the stunnel service watches for changes in the entire certificate
  space.
- Changed all instances of defined(Class['foo']) to defined('foo') per the
  directions from the Puppet mailing list.
- Updated to use concat_build and concat_fragment types.

* Tue Jan 11 2011 Maintenance
2.0.0-0
- Refactored for SIMP-2.0.0-alpha release

* Tue Oct 26 2010 Maintenance - 1-2
- Converting all spec files to check for directories prior to copy.

* Wed Jul 14 2010 Maintenance
1.0-1
- Updated stunnel to start at runlevel 15 and ensured that it updated its
  chkconfig entires approprately

* Tue May 25 2010 Maintenance
1.0-0
- Code refactoring.

* Thu Feb 18 2010 Maintenance
0.1-11
- Added a paramater $client_nets to the stunnel_add define to allow users to
  lock down access to the encrypted port via IPTables.

* Thu Oct 08 2009 Maintenance
0.1-10
- Finally fixed the problem with cert verification.  All uses of stunnel can now
  set verify to 1 or 2.
