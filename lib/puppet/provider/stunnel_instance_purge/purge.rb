Puppet::Type.type(:stunnel_instance_purge).provide(:purge) do
  desc 'Provider for purging expired ``stunnel::instance`` resources'

  confine :kernel => 'Linux'

  def change_to_s
    return @state_msg
  end

  def dirs
    # Shortcut for preventing a change notification
    @state_msg = resource[:dirs]

    begin

      @system_services = Puppet::Resource::indirection.search('Service', {}).select do |s|
        s.title =~ %r(^#{@resource[:name]})
      end

    rescue Puppet::Error
      @system_services = nil
    end

    if @system_services
      matching_catalog_services = @resource.catalog.resources.find_all do |res|
        res.is_a?(Puppet::Type.type(:service)) && res[:name] =~ %r(^#{@resource[:name]})
      end

      system_service_names = @system_services.map(&:title)
      matching_catalog_service_names = matching_catalog_services.map(&:name)

      # Handle systemd
      if system_service_names.first && system_service_names.first.split('.')[-1] == 'service'
        matching_catalog_service_names.map!{|n| n = n + '.service'}
      end

      rogue_services = system_service_names - matching_catalog_service_names

      if rogue_services && !rogue_services.empty?
        @to_purge = rogue_services

        if @resource[:verbose] || @resource[:noop]
          @state_msg = %(Purged Services: '#{@to_purge.join("', '")}')
        else
          @state_msg = %(Purged '#{@to_purge.count}' Services)
        end
      end
    end

    return @state_msg
  end

  def dirs=(target_dirs)
    # Disable all non-managed services
    @system_services.select{|s| @to_purge.include?(s.title) }.each do |service|

      service_name = File.basename(service.title, '.service')

      begin
        Puppet.debug("Stopping Service #{service_name}")

        service.to_ral.provider.send('stop')
      rescue Puppet::Error
        # noop
      end

      begin
        Puppet.debug("Disabling Service #{service_name}")

        service.to_ral.provider.send('disable')
      rescue Puppet::Error
        # noop
      end

      Array(target_dirs).each do |dir|
        Dir.glob(File.join(dir, "#{service_name}*")).each do |to_delete|
          if Puppet::FileSystem.file?(to_delete)
            Puppet.debug("Purging File '#{to_delete}'")

            Puppet::FileSystem.unlink(to_delete)
          else
            Puppet.debug("Refusing to Purge Non-File '#{to_delete}'")
          end
        end
      end
    end
  end
end
