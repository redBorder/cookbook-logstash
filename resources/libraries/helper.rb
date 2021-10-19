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
  end
end
