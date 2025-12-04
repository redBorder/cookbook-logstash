module Logstash
  module Helper
    def get_managers
      sensors = []
      managers_keys = Chef::Node.list.keys.sort
      managers_keys.each do |m_key|
        m = Chef::Node.load m_key
        m = node if m.name == node.name

        begin
          roles = m['roles']
        rescue NoMethodError
          begin
            roles = m.run_list
          rescue
            roles = []
          end
        end

        next unless roles

        if roles.include?('manager')
          sensors << m
        end
      end
      sensors
    end

    def get_namespaces
      namespaces = []
      Chef::Role.list.each_key do |rol|
        ro = Chef::Role.load rol
        next unless ro && ro.override_attributes['redborder'] &&
                    ro.override_attributes['redborder']['namespace'] &&
                    ro.override_attributes['redborder']['namespace_uuid'] &&
                    !ro.override_attributes['redborder']['namespace_uuid'].empty?

        namespaces.push(ro.override_attributes['redborder']['namespace_uuid'])
      end

      namespaces.uniq
    end

    def get_sensors_info(sensor_type)
      sensors = []
      managers_keys = Chef::Node.list.keys.sort
      managers_keys.each do |m_key|
        m = Chef::Node.load m_key
        m = node if m.name == node.name

        begin
          roles = m['roles']
        rescue NoMethodError
          begin
            roles = m.run_list
          rescue
            roles = []
          end
        end

        next unless roles && !roles.empty? && !roles.include?('manager')

        case sensor_type
        when 'ips-sensor'
          if roles.include?('ips-sensor') || roles.include?('ipsv2-sensor') || roles.include?('ipscp-sensor')
            sensors << m
          end
        when 'cep-sensor'
          if m.respond_to?('run_list') &&
             (m.run_list.map(&:name).include?('vault-sensor') || m.run_list.map(&:name).include?('cep-sensor'))
            sensors << m
          end
        else
          if m.respond_to?('run_list') &&
             m.run_list.map(&:name).include?(sensor_type)
            sensors << m
          end
        end
      end
      sensors
    end

    def bulkstats_monitors?(device_nodes)
      return false unless device_nodes

      device_nodes.each do |monitor|
        next unless monitor['redborder']['monitors']

        monitor['redborder']['monitors'].each do |dmonitor|
          return true if dmonitor['system'].to_s.start_with?('bulkstats')
        end
      end

      false
    end

    def redfish_monitors?(device_nodes)
      return false unless device_nodes

      device_nodes.each do |monitor|
        next unless monitor['redborder']['monitors']

        monitor['redborder']['monitors'].each do |dmonitor|
          if dmonitor['system'].is_a?(String) && dmonitor['system'].split().first == 'redfish'
            return true
          end
        end
      end

      false
    end

    def is_proxy?
      node.role?('proxy-sensor')
    end

    def is_manager?
      node.role?('manager')
    end
  end
end
