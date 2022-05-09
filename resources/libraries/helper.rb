module Logstash
  module Helper

    def get_managers
      sensors = []
      managers_keys = Chef::Node.list.keys.sort
      managers_keys.each do |m_key|
        m = Chef::Node.load m_key
        m = node if m.name == node.name

        begin
          roles = m.roles
        rescue NoMethodError
          begin
            roles = m.run_list
          rescue
            roles = []
          end
        end

        unless roles.nil?
          if roles.include?("manager")
            sensors << m
          end
        end
      end
      sensors
    end

    def get_namespaces
      namespaces = []
      Chef::Role.list.keys.each do |rol|
        ro = Chef::Role.load rol
        if ro and ro.override_attributes["redborder"] and ro.override_attributes["redborder"]["namespace"] and ro.override_attributes["redborder"]["namespace_uuid"] and !ro.override_attributes["redborder"]["namespace_uuid"].empty?
          namespaces.push(ro.override_attributes["redborder"]["namespace_uuid"])
        end
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
          roles = m.roles
        rescue NoMethodError
          begin
            roles = m.run_list
          rescue
            roles = []
          end
        end

        unless roles.nil?
          if !roles.empty? and !roles.include?("manager")
            case sensor_type
            when "ips-sensor"
              if roles.include?("ips-sensor") or roles.include?("ipsv2-sensor") or roles.include?("ipscp-sensor")
                sensors << m
              end
            when "cep-sensor"
              if m.respond_to?"run_list" and (m.run_list.map{|x| x.name}.include?"vault-sensor" or m.run_list.map{|x| x.name}.include?"cep-sensor")
                sensors << m
              end
            else
              if m.respond_to?"run_list" and m.run_list.map{|x| x.name}.include?(sensor_type)
                sensors << m
              end
            end
          end
        end
      end
      sensors
    end

    def check_proxy_monitors(device_nodes)
      has_redfish_monitors = false
      has_bulkstats_monitors = false

      unless device_nodes.nil?
        device_nodes.each do |monitor|
          Chef::Log.info monitor
          if monitor["redborder"]["monitors"]
            monitor["redborder"]["monitors"].each do |dmonitor|
              has_redfish_monitors =  (dmonitor["system"].split().first == "redfish" or has_redfish_monitors)
              has_bulkstats_monitors = (dmonitor["system"].to_s.start_with? "bulkstats" or has_bulkstats_monitors)
            end
          end
        end
      end
      Chef::Log.info has_bulkstats_monitors
      return (has_bulkstats_monitors || has_redfish_monitors), has_bulkstats_monitors, has_redfish_monitors
    end
  end
end
