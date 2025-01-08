module Logstash
  module Helper
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
          return true if dmonitor['system'].split().first == 'redfish'
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
