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

require 'spec_helper'
require 'component_helper'
require 'java_buildpack/framework/snyk'

describe JavaBuildpack::Framework::Snyk do
  include_context 'with component help'

  it 'does not detect without snyk service' do
    expect(component.detect).to be_nil
  end

  context do

    before do
      allow(services).to receive(:one_service?)
        .with(/snyk/, 'apiToken', 'apiUrl', 'orgName').and_return(true)

      allow(services).to receive(:find_service)
        .with(/snyk/, 'apiToken', 'apiUrl', 'orgName')
        .and_return(
          'credentials' => {
            'apiToken' => '01234567-8901-2345-6789-012345678901',
            'apiUrl' => 'https://my.internal.snyk/api',
            'orgName' => 'my-org'
          }
        )
    end

    it 'detects with snyk service' do
      expect(component.detect).to eq('snyk')
    end

  end

end
