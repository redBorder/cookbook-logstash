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
    def input_kafka(pipelines_dir, pipeline, topic)
      template "#{pipelines_dir}/#{pipeline}/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: [topic])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end
  end
end
