# Snyk Framework
The Snyk Framework causes an application to be automatically configured to work with a bound [Snyk Service][].
Binding an application to the service will cause the buildpack to check for vulnerable dependencies and break the build process
if found any, for a given severity threshold.

<table>
  <tr>
    <td><strong>Detection Criterion</strong></td><td>Existence of a bound Snyk service.
      <ul>
        <li>Existence of a Snyk service is defined as the <a href="http://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html#VCAP-SERVICES"><code>VCAP_SERVICES</code></a> payload containing a service who's name, label or tag has <code>snyk</code> as a substring.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td><strong>Tags</strong></td>
    <td><tt>snyk</td>
  </tr>
</table>
Tags are printed to standard output by the buildpack detect script

## User-Provided Service (Optional)
Users may optionally provide their own Snyk service. A user-provided Snyk service must have a name or tag with `snyk` in it so that the Snyk Framework will automatically configure the application to work with the service.

The credential payload of the service may contain the following entries:

| Name | Description
| ---- | -----------
| `apiToken` | The snyk api token used to authenticate against the api endpoint.
| `apiUrl` | (Optional) The url of the snyk api endpoint. Should be of the form `https://my.snyk.server:port/api`. Defaults to `https://snyk.io/api`
| `orgName` | (Optional) The organization for the snyk service to use. If not provided, snyk api will use the user's default organization.

## Configuration
For general information on configuring the buildpack, including how to specify configuration values through environment variables, refer to [Configuration and Extension][].

The framework can be configured with additional (optional) values through environment variables.

| Name | Description
| ---- | -----------
| `fail_build` | Specifies whether to fail the build on discovery of vulnerabilities above the `severity_threshold`.  Defaults to `true`.
| `org_name` | Specifies an override of the organization name in the service credential payload.  Defaults to using the service credential payload.
| `severity_threshold` | Specifies the threshold at which Snyk will report vulnerabilities and optionally fail the build.  Legal values are `low`, `medium`, and `high`.  Defaults to `low`. 

[Snyk Service]: https://snyk.io
[Configuration and Extension]: ../README.md#configuration-and-extension
