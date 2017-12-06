#! /usr/bin/env ruby -S rspec
require 'spec_helper'

provider_class = Puppet::Type.type(:stunnel_instance_purge).provider(:purge)

describe provider_class do
  let :verbose do
    false
  end

  let :resource do
    Puppet::Type::Stunnel_instance_purge.new(
      {
        :name    => 'test',
        :dirs    => ['/foo'],
        :verbose => verbose
      }
    )
  end

  let :provider do
    # Don't hit the local system
    Puppet::Resource::indirection.stubs(:search).with('Service', {}).returns([])

    provider_class.new(resource)
  end

  describe '#dirs' do
    before(:each) do
      @catalog = Puppet::Resource::Catalog.new('Stunnel Test', 'production')
      @catalog.add_resource(resource)
    end

    it 'does not have any changes' do
      # No changes should be expected here so we return what we were passed
      expect(provider.dirs).to eq(resource[:dirs])
    end

    context 'with additional services' do
      let :provider do
        # Don't hit the local system
        Puppet::Resource::indirection.stubs(:search).with('Service', {}).returns([
          Puppet::Resource.new(:service, 'test_should_be_purged'),
          Puppet::Resource.new(:service, 'should_not_be_purged')
        ])

        provider_class.new(resource)
      end

      it 'should purge rogue services' do
        expect(provider.dirs).to eq(%(Purged '1' Services))
      end

      context 'when verbose' do
        let :verbose do
          true
        end

        it 'should purge rogue services and dislay their names' do
          expect(provider.dirs).to eq(%(Purged Services: 'test_should_be_purged'))
        end
      end
    end
  end
end
