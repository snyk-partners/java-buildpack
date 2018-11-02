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

    # Encapsulates the functionality for using Snyk to test for known vulnerabilities.
    class Snyk < JavaBuildpack::Component::BaseComponent

      # (see JavaBuildpack::Component::BaseComponent#detect)
      def detect
        enabled? ? self.class.to_s.dash_case : nil
      end

      # (see JavaBuildpack::Component::BaseComponent#compile)
      # This is to change the FS
      def compile
        puts "#{'----->'.red.bold} Scanning with #{'Snyk'.blue.bold} " \
             "(#{fail_build? ? 'failure' : 'warning'} on #{severity_threshold} severity vulnerabilities)"

        manifests = poms
        if manifests.empty?
          puts '       No manifests found'.yellow
          return
        end

        payload = request manifests
        issues  = issues payload

        print_issues issues
        print_summary issues, payload

        return if issues.empty? || !fail_build?

        raise 'Snyk scan found vulnerabilities'
      end

      # (see JavaBuildpack::Component::BaseComponent#release)
      def release; end

      private

      API_TOKEN = 'apiToken'

      API_URL = 'apiUrl'

      FAIL_BUILD = 'fail_build'

      FILTER = /snyk/

      ORG_NAME = 'orgName'

      ORG_NAME_CONFIG = 'org_name'

      private_constant :API_TOKEN, :API_URL, :FAIL_BUILD, :FILTER, :ORG_NAME, :ORG_NAME_CONFIG

      def api_token
        credentials[API_TOKEN]
      end

      def api_url
        credentials[API_URL] || 'https://snyk.io/api'
      end

      def credentials
        @application.services.find_service(FILTER, API_TOKEN)['credentials']
      end

      def enabled?
        @application.services.one_service? FILTER, API_TOKEN
      end

      def extract_issues(payload)
        issues = []
        issues += payload['vulnerabilities'] if payload.key? 'vulnerabilities'

        if payload.key? 'issues'
          issues += payload['issues']['vulnerabilities'] if payload['issues'].key? 'vulnerabilities'
          issues += payload['issues']['licenses'] if payload['issues'].key? 'licenses'
        end

        issues
      end

      def fail_build?
        @configuration[FAIL_BUILD].nil? || @configuration[FAIL_BUILD]
      end

      def filesystem_poms
        (@application.root + '**/pom.xml').glob(File::FNM_DOTMATCH).reject(&:directory?).sort.map { |f| File.read(f) }
      end

      def issues(payload)
        scores    = { 'high' => 3, 'medium' => 2, 'low' => 1 }
        threshold = scores[severity_threshold]

        extract_issues(payload)
          .map { |issue| [scores[issue['severity']], issue] }
          .select { |score, _| score >= threshold }
          .sort { |left, right| left[0] - right[0] }
          .map { |_, issue| issue }
      end

      def issue_summary(issue, severity)
        summary = "       ✗ #{severity.capitalize} severity vulnerability found in #{issue['package'].underline}"

        if severity == 'high'
          summary.red
        elsif severity == 'medium'
          summary.yellow
        elsif severity == 'low'
          summary.blue
        end
      end

      def jar_poms
        (@application.root + '**/*.jar')
          .glob(File::FNM_DOTMATCH).reject(&:directory?).sort
          .map do |jar|
          `unzip -Z1 #{jar} | grep "pom\.xml"`.split("\n").map do |pom|
            `unzip -p #{jar} #{pom}`
          end
        end
      end

      def org_name
        @configuration[ORG_NAME_CONFIG] || credentials[ORG_NAME]
      end

      def poms
        (filesystem_poms + jar_poms).flatten
      end

      def print_issues(issues)
        issues.each do |issue|
          puts issue_summary(issue, issue['severity'])
          puts "         Description:        #{issue['title']}"
          puts "         Info:               #{issue['url'].underline}"
          puts "         Introduced through: #{issue['from'][0]}"
          puts "         From:               #{issue['from'].join(' > ')}"
          puts ''
        end
      end

      def print_summary(issues, payload)
        if issues.empty?
          result = 'No vulnerabilities found.'.green
        else
          unique_count     = issues.map { |issue| issue['id'] }.uniq.length
          vulnerable_paths = issues.map { |issue| issue['from'] }.flatten.length

          result = "Found #{unique_count} vulnerabilities in #{vulnerable_paths} vulnerable paths."
          result = fail_build? ? result.red : result.yellow
        end

        puts "       Tested #{payload['dependencyCount'] || 0} dependencies. #{result}"
      end

      def request(poms)
        uri       = URI("#{api_url}/v1/test/maven")
        uri.query = URI.encode_www_form(org: org_name) if org_name

        body                        = { 'encoding' => 'plain', 'files' => { 'target' => { 'contents' => poms[0] } } }
        body['files']['additional'] = poms[1..-1].map { |pom| { 'contents' => pom } } if poms.length > 1

        request                  = Net::HTTP::Post.new(uri)
        request['Content-Type']  = 'application/json'
        request['Authorization'] = "token #{api_token}"
        request.body             = body.to_json

        Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
          JSON.parse http.request(request).body
        end
      end

      def severity_threshold
        (@configuration['severity_threshold'] || 'low').downcase
      end

    end

  end
end
