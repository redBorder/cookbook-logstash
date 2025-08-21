# frozen_string_literal: true

module Logstash
  # Módulo con métodos para definir filtros, inputs y outputs para Logstash
  module Filters
    # Singleton class para construir filtros de Logstash en base a plantillas de chef
    class FilterBuilder
      attr_reader :pipelines_dir

      # El constructor obliga a pasar pipelines_dir
      def initialize(pipelines_dir:)
        @pipelines_dir = pipelines_dir
      end

      # Inputs y Outputs
      def input_template(pipeline:, topic:)
        input_kafka(pipelines_dir: @pipelines_dir, pipeline: pipeline, topic: topic)
      end

      def output_template(pipeline:, topic:)
        output_kafka(pipelines_dir: @pipelines_dir, pipeline: pipeline, topic: topic)
      end

      # Filtros netflow
      def macscrambling(pipeline: 'netflow', index: '01')
        macscrambling pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def geoenrich(pipeline: 'netflow', index: '02')
        geoenrich pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def macvendor(pipeline: 'netflow', index: '03')
        macvendor pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def threat_intelligence(pipeline: 'netflow', index: '05')
        threat_intelligence pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def check_license(pipeline: 'netflow', index: '06')
        check_license pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def assets(pipeline: 'netflow', index: '08')
        assets pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def discard_events(pipeline: 'netflow', index: '85')
        discard_events pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def splitflow(pipeline: 'netflow', index: '90')
        splitflow pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end

      def rename(pipeline: 'netflow', index: '91')
        rename pipelines_dir: @pipelines_dir, pipeline: pipeline, index: index
      end
    end
  end
end
