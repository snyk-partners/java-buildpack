# frozen_string_literal: true

# Cloud Foundry Java Buildpack
# Copyright 2013-2018 the original author or authors.
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

module JavaBuildpack
  module Framework

    # Encapsulates the functionality for using Snyk to test for known
    # vulnerabilities.
    class Snyk < JavaBuildpack::Component::BaseComponent

      # Creates an instance
      #
      # @param [Hash] context a collection of utilities used the component
      def initialize(context)
        super(context)
        @logger = JavaBuildpack::Logging::LoggerFactory.instance.get_logger Snyk
      end

      # (see JavaBuildpack::Component::BaseComponent#detect)
      def detect
        @logger.debug 'Checking if Snyk service is enabled...'
        if enabled?
          @logger.debug 'Snyk token was found.'
          return self.class.to_s.dash_case.to_s
        else
          @logger.debug 'Snyk token wasn\'t found...'
          return nil
        end
      end

      # (see JavaBuildpack::Component::BaseComponent#compile)
      # This is to change the FS
      def compile
        @logger.info 'Run Snyk test...'
        @logger.info "SNYK_DONT_BREAK_BUILD: #{dont_break_build}" if dont_break_build
        @logger.info "SNYK_SEVERITY_THRESHOLD: #{severity_threshold}" if severity_threshold

        begin
          is_ok = do_test
        rescue StandardError => e
          @logger.error "Failed to run Snyk test: #{e}"
          raise
        end

        if is_ok
          @logger.info 'Snyk finished successfully!'.green
          return
        end

        @logger.warn 'Snyk found vulnerabilities!'.red

        if dont_break_build == 'true'
          @logger.warn 'SNYK_DONT_BREAK_BUILD was defined, continue build despite vulnerabilities found'.yellow
          return
        end

        @logger.error 'Failing build...'.red
        raise 'Snyk found vulnerabilities!'
      end

      # (see JavaBuildpack::Component::BaseComponent#release)
      def release; end

      private

      def do_test
        target_pom, additional_poms = gather_pom_files
        if target_pom.empty?
          @logger.warn 'no manifest files found'.yellow
          return true
        end

        test_result = do_query(target_pom, additional_poms)
        issues = sort_out_issues(test_result)
        print_results(test_result, issues)
        test_result['ok']
      end

      def do_query(target_pom, additional_poms)
        uri, request = construct_request(target_pom, additional_poms)
        response = do_request(uri, request)
        JSON.parse(response.body)
      end

      def construct_request(target_pom, additional_poms)
        request_body = {
          'encoding' => 'plain',
          'files' => {
            'target' => {
              'contents': target_pom
            }
          }
        }

        unless additional_poms.empty?
          request_body['files']['additional'] = additional_poms.map { |pom| { 'contents': pom } }
        end

        uri = URI("#{api_url}/v1/test/maven")
        uri.query = URI.encode_www_form(org: org_name) if org_name && !org_name.empty?

        request = Net::HTTP::Post.new(uri)
        request.body = request_body.to_json
        request['Content-Type'] = 'application/json'
        request['Authorization'] = "token #{api_token}"

        [uri, request]
      end

      def do_request(uri, request)
        https = Net::HTTP.new(uri.host, uri.port)
        https.use_ssl = true
        begin
          response = https.request(request)
        rescue StandardError => e
          @logger.error "Failed to connet to \"#{uri}\": #{e}"
          raise
        end

        raise "HTTP error #{response.code} #{response.message}" unless response.is_a? Net::HTTPSuccess

        response
      end

      def gather_pom_files
        target_pom_path = find_main_pom
        target_pom = target_pom_path ? File.read(target_pom_path) : ''
        additional_poms = all_jars.map { |jar| poms_from_jar(jar) }.flatten

        return [target_pom, additional_poms] unless target_pom.empty?
        return [additional_poms[0], additional_poms[1..-1]] unless additional_poms.empty?

        ['', []]
      end

      def find_main_pom
        @logger.debug "searching for pom.xml under #{@application.root}"
        poms = Dir.glob("#{@application.root}/**/pom.xml").sort
        @logger.debug "found #{poms.length} pom.xml files: #{poms}"
        poms[0]
      end

      def all_jars
        @logger.debug "searching for .jar under #{@application.root}"
        jars = Dir.glob("#{@application.root}/**/*.jar").sort
        @logger.debug "found #{jars.length} .jar files: #{jars}"
        jars
      end

      def poms_from_jar(jar)
        poms = `unzip -Z1 #{jar} | grep "pom\.xml"`.split('\n')
        @logger.debug "found #{poms.length} pom.xml files in #{jar}: #{poms}" unless poms.empty?
        poms.map { |pom| `unzip -p #{jar} #{pom}` }
      end

      def sort_out_issues(test)
        issues = []
        issues.concat(test['vulnerabilities']) if test.key?('vulnerabilities')
        if test.key?('issues') && test['issues'].key?('vulnerabilities')
          issues.concat(test['issues']['vulnerabilities'])
        end
        issues.concat(test['issues']['licenses']) if test.key?('issues') && test['issues'].key?('licenses')

        issues = sort_issues(issues)
        issues = filter_issues(issues, severity_threshold) if severity_threshold
        issues
      end

      def print_results(test, issues)
        @logger.info ' '
        @logger.info "Testing #{@application.details['application_name']}...".white.bold
        @logger.info ' '

        issues.each do |issue|
          print_issue(issue)
        end

        print_test_summary(test, issues)
        @logger.info ' '
      end

      def print_issue(issue)
        severity = issue['severity']
        color = {
          'high' => "\e[31m",
          'medium' => "\e[1;33m",
          'low' => "\e[34m"
        }[severity]

        @logger.info "\e[0m#{color}✗ #{severity.capitalize} severity vulnerability " \
          "found in #{issue['package'].underline}\e[0m"
        @logger.info "\e[0m  Description: #{issue['title']}"
        @logger.info "\e[0m  Info: #{issue['url'].underline}"
        @logger.info "\e[0m  Introduced through: #{issue['from'][0]}"
        @logger.info "\e[0m  From: #{issue['from'].join(' > ')}"
        @logger.info ' '
      end

      def print_test_summary(test, issues)
        dependency_count = test['dependencyCount'] || 0
        if issues.empty?
          @logger.info "✓ Tested #{dependency_count} dependencies for known vulnerabilities, " \
            'no vulnerable paths found'.green
        else
          unique_count = issues.map { |issue| issue['id'] }.uniq.length
          vulnerable_paths = issues.map { |issue| issue['from'] }.flatten.length
          @logger.info "\e[0mTested #{dependency_count} dependencies for known " \
            "vulnerabilities, #{"found #{unique_count} vulnerabilities, " \
            "#{vulnerable_paths} vulnerable paths.".red}"
        end
      end

      def severity_score(severity)
        {
          'high' => 3,
          'medium' => 2,
          'low' => 1
        }[severity]
      end

      def sort_issues(issues)
        issues.sort { |left, right| severity_score(left['severity']) - severity_score(right['severity']) }
      end

      def filter_issues(issues, threshold)
        score = severity_score(threshold)
        issues.select { |issue| severity_score(issue['severity']) >= score }
      end

      def enabled?
        api_token != nil
      end

      def credentials
        svc = @application.services.find_service(FILTER, API_TOKEN, API_URL, ORG_NAME)
        svc ? svc['credentials'] : {}
      end

      def api_token
        @application.environment['SNYK_TOKEN'] || credentials[API_TOKEN]
      end

      def api_url
        @application.environment['SNYK_API'] || credentials[API_URL] || 'https://snyk.io/api'
      end

      def org_name
        @application.environment['SNYK_ORG_NAME'] || credentials[ORG_NAME]
      end

      def severity_threshold
        @application.environment['SNYK_SEVERITY_THRESHOLD']
      end

      def dont_break_build
        @application.environment['SNYK_DONT_BREAK_BUILD']
      end

      FILTER = /snyk/

      API_TOKEN = 'apiToken'

      API_URL = 'apiUrl'

      ORG_NAME = 'orgName'

      private_constant :FILTER, :API_TOKEN, :API_URL, :ORG_NAME
    end

  end
end
