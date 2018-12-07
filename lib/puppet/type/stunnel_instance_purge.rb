require 'puppet/parameter/boolean'

Puppet::Type.newtype(:stunnel_instance_purge) do
  desc <<-EOM
    Disables all services and removes all associated files for
    ``stunnel::instance`` created resources that are no longer under
    management.

    This is required so that newly created resources do not have port conflicts
    upon starting a new service.

    Example:

      stunnel_instance_purge { 'stunnel_managed_by_puppet':
        dirs => [
          '/etc/stunnel',
          '/etc/rc.d/init.d',
          '/etc/systemd/system'
        ]
      }

      This will disable all services that start with ``$namevar`` and will
      subsequently remove all files in the directories specified in the
      ``$dirs`` Array that match ``${dir}/${namevar}.*``.

      WARNING: BE VERY CAREFUL THAT ${namevar} IS PRECISE
  EOM

  newparam(:name, :namevar => true) do
    desc 'The prefix name of the services to disable and files to remove'
  end

  newparam(:verbose, :boolean => true, :parent => Puppet::Parameter::Boolean) do
    desc 'Provide verbose output in the change message regarding services to be purged'
  end

  newproperty(:dirs, :array_matching => :all) do
    desc 'The directories from which the files matching "${name}.*" should be purged'

    # Must be an absolute path
    newvalues(/^\//)

    def change_to_s(from, to)
      to_purge = provider.change_to_s

      to_purge
    end
  end

  autobefore(:service) do
    # We find all of the relevant stunnel instances and tack on things that
    # match 'stunnel' to eliminate all possibility of conflicts on service
    # restarts
    catalog.resources.find_all do |r|
      r.is_a?(Puppet::Type.type(:service)) && (r[:name] =~ /^(stunnel|#{self[:name]})/)
    end.map(&:title)
  end
end
