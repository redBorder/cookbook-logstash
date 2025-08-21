# frozen_string_literal: true

module Logstash
  # Módulo con métodos para definir filtros, inputs y outputs para Logstash
  module Filters
    # Crea el input Kafka para un pipeline dado
    #
    # @param pipelines_dir [String] Ruta base de los pipelines
    # @param pipeline [String] Nombre del pipeline
    # @param topic [String] Topic de Kafka por donde recibir mensajes
    #
    # Ejemplo:
    #   output_kafka('/etc/logstash/pipelines', 'vault', 'rb_vault')

    def macscrambling(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_macscrambling.conf" do
        source 'netflow_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def geoenrich(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_geoenrich.conf" do
        source 'netflow_geoenrich.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def macvendor(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_macvendor.conf" do
        source 'netflow_macvendor.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server,
                  mac_vendors: mac_vendors)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def threat_intelligence(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_threat_intelligence.conf" do
        source 'netflow_threat_intelligence.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_servers: memcached_servers, flow_nodes: flow_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def check_license(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: flow_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def assets(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_assets.conf" do
        source 'netflow_assets.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def discard_events
      template "#{pipelines_dir}/#{pipeline}/#{index}_discard_events.conf" do
        source 'netflow_discard_events.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def splitflow(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_splitflow.conf" do
        source 'netflow_splitflow.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    def rename(pipelines_dir:, pipeline:, index:)
      template "#{pipelines_dir}/#{pipeline}/#{index}_rename.conf" do
        source 'netflow_rename.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end
  end
end
