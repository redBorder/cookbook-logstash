# frozen_string_literal: true

module Logstash
  # Módulo con métodos para definir filtros, inputs y outputs para Logstash
  module Filter
    # Singleton class para construir filtros de Logstash en base a plantillas de chef
    class FilterBuilder
      attr_reader :pipelines_dir

      # El constructor obliga a pasar pipelines_dir
      def initialize(pipelines_dir:)
        @pipelines_dir = pipelines_dir
      end

      # Método genérico para crear input templates
      def input_template(pipeline:, topic:)
        input_kafka(pipelines_dir: @pipelines_dir, pipeline: pipeline, topic: topic)
      end

      def output_template(pipeline:, topic:)
        output_kafka(pipelines_dir: @pipelines_dir, pipeline: pipeline, topic: topic)
      end
    end
  end
end
