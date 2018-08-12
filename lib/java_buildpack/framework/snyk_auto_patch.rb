# Cloud Foundry Java Buildpack
# Copyright 2013-2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'fileutils'
require 'yaml'
require 'java_buildpack/component/versioned_dependency_component'
require 'java_buildpack/logging/logger_factory'
require 'java_buildpack/framework'
require 'net/http'
require 'json'
require 'rubygems'

SNYK_API_URL = "https://snyk.io/api/v1/test/maven"

module JavaBuildpack
  module Framework

    # Encapsulates the detect, compile, and release functionality for enabling cloud auto-reconfiguration in Spring
    # applications.
    class SnykAutoPatch < JavaBuildpack::Component::VersionedDependencyComponent

      # Creates an instance
      #
      # @param [Hash] context a collection of utilities used the component
      def initialize(context)
        super(context)
        @logger = JavaBuildpack::Logging::LoggerFactory.instance.get_logger SnykAutoPatch
      end

      # (see JavaBuildpack::Component::BaseComponent#compile)
      # This is to change the FS
      def compile
        pom_path = Dir.glob("#{@droplet.root}/**/pom.xml")[0]
        uri = URI.parse(SNYK_API_URL)
        req = Net::HTTP::Post.new(uri.to_s)
        https = Net::HTTP.new(uri.host,uri.port)
        https.use_ssl = true
        req['Content-Type'] = 'application/json'
        req['Authorization'] = 'token ' + @application.environment["SNYK_TOKEN"]
        data = File.read(pom_path)
        test_request = {
          'encoding' => 'plain', 
          'files' => {
              'target' => {
                "contents": ""
              },              
          }
        }
        test_request['files']['target']['contents'] = data

        additional = []
        jars = Dir.glob("#{@droplet.root}/WEB-INF/**/*.jar")
        jars.each do |jar|
            jar_pom_path = `unzip -Z1 #{jar} | grep "pom.xml"`
            if (jar_pom_path.length) > 0 then        
                poms = jar_pom_path.split("\n")
                poms.each do |pom|
                    pom_content = `unzip -p #{jar} #{pom}`
                    additional.push({"contents" => pom_content})
                end
            end
        end
        test_request['files']['additional'] = additional;

        req.body = test_request.to_json
        response = https.request(req)
        res = JSON.parse(response.body)
        if res['ok'] then
          puts "Tested #{res['dependencyCount']} 0 vulnerabilties were found!"
        else
          issues = res.key?('issues') ? res['issues'] : res['vulnerabilities']
          vulns = issues['vulnerabilities']
          severityMap = {
            'high' => 3,
            'medium' => 2,
            'low' => 1
          }
          vulns.sort! do |vuln_a, vuln_b|
              vulna_map = severityMap[vuln_a['severity']]
              vulnb_map = severityMap[vuln_b['severity']]
              if (vulna_map > vulnb_map) 
                1
              elsif (vulna_map < vulnb_map) 
                -1
              else
                0
              end
          end
          puts "\nFounded #{vulns.length} vulnerabilities on #{res['dependencyCount']} dependencies\n"
          vulns.each do |vuln| 
              severity = vuln['severity']
              if (severity == 'high') then
                  color = "\e[31m"            
              elsif (severity == 'medium') then
                  color = "\e[1;33m"
              else
                  color = "\e[34m"
              end
              puts "\n#{color}✗ #{severity.capitalize} severity vulnerabiltity found in #{vuln['package']}\e[0m"
              puts "  Description: #{severity} severity vulnerabiltity found in #{vuln['package']}"
              puts "  Info: #{vuln['url']}"
              puts "  Introduce through: #{vuln['from'][0]}\n"
          end 
          
          raise "Terminating droplet compilation as Snyk detected vulnerabilties..."
        end
      end

      # (see JavaBuildpack::Component::BaseComponent#release)
      # This is for runtime configuration (Env var and etc..)
      def release
      end

      protected

      # (see JavaBuildpack::Component::VersionedDependencyComponent#supports?)
      def supports?
        @configuration['enabled']
      end
    end

  end
end
