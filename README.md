# polaris-analysis
Will analyze the source code with Polaris by using the polaris Command Line tool. https://sig-docs.synopsys.com/polaris/topics/c_cli-overview.html

## Prerequisities
This action expects that Polaris thin-client is in the runner PATH. That can be done with running the [synopsys-sig-community/setup-polaris-analysis](https://github.com/synopsys-sig-community/setup-polaris-analysis) first.

## Available Options
| Option name | Description | Default value | Required |
|-------------|-------------|---------------|----------|
| project     | Project name in Polaris, if not given then default=github.repository | ${{github.repository}} | false |
| branch      | Project branch name in Polaris, if not given then default=github.ref_name | ${{github.ref_name}} | false |
| log_level | Logging level. Default is INFO | INFO | false 
| polaris_config_overrides | With this you can overriding the configuration file. More info: https://sig-docs.synopsys.com/polaris/topics/c_cli-config-overrides.html" | --co analyze.coverity.cov-analyze='["--enable", "HARDCODED_CREDENTIALS", "--security", "--webapp-security", "--android-security"]' | false |
| polaris_analysis_mode | Analysis mode will tell the action that is local or central analysis requested, Options are local and central (Default). | central | false |
| polaris_config_file | By giving this input, you specify which polaris.yaml file to use. If this is given, then only configurations given inside of the config file, will be used. If not given then will set polaris server url with flag -s | - | false |
| polaris_sarif | By setting this true, you will get results output as a sarif format file. Default is false. | false | false |
| polaris_sarif_file | If polaris_sarif: true, then this is used, to specify the output file with full path. Default: github.workspace/polaris-scan-results.sarif.json | ${{github.workspace}}/polaris-scan-results.sarif.json | false |
| build_command | Application build command. Ex. mvn clean install | - | false |

## Environment variables what this action expects

These key-value pairs must be in environment values and are accessed with **${{env.key}}**
| Key | Value | Description |
|----------|--------|---------|
| POLARIS_SERVER_URL | ${{env.polaris_url}} | Polaris server URL. Ex. https://polaris.com |
| POLARIS_ACCESS_TOKEN | ${{env.polaris_token}} | Polaris Access Token for REST APIs |

## Usage examples
Run the Polaris analysis with given polaris config, build command and request sarif format file as a result.
```yaml
    - name: Analyze with Polaris
      uses: synopsys-sig-community/polaris-analysis@main
      with:
        polaris_config_file: polaris.yml
        build_command: mvn package
        polaris_sarif: true
```

**Run Polaris analysis without config-file**

This will run the Polaris analysis and request Sarif -format report. The report will be in: ${{github.workspace}}/polaris-scan-results.sarif.json
```yaml
    - name: Analyze with Polaris
      uses: synopsys-sig-community/polaris-analysis@main
      with:
        polaris_sarif: true
```

**Full pipeline with [setup-polaris-analysis](https://github.com/synopsys-sig-community/setup-polaris-analysis)**
```yaml
name: Java CI with Maven and Polaris

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3 # This will checkout the source codes from repository

    - name: Set up JDK 1.11 # This will add Java into the runners PATH
      uses: actions/setup-java@v3.6.0
      with:
        java-version: '11'
        distribution: 'temurin'
        cache: 'maven'

    - name: Set up Polaris # This will add Polaris tools into runner PATH
      uses: synopsys-sig-community/setup-polaris-analysis@main
      with:
        polaris_url: ${{secrets.POLARIS_SERVER_URL}} #Polaris server URL
        polaris_token: ${{secrets.POLARIS_ACCESS_TOKEN}} #Polaris Access Token
    
    - name: Analyze with Polaris
      uses: synopsys-sig-community/polaris-analysis@main
      with:
        polaris_config_file: polaris.yml
        build_command: mvn package
        polaris_sarif: true

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        # Path to SARIF file
        sarif_file: ${{github.workspace}}/polaris-scan-results.sarif.json
      continue-on-error: true

    - name: Archive scanning results
      uses: actions/upload-artifact@v3
      with:
        name: polaris-scan-results
        path: ${{github.workspace}}/polaris-scan-results.sarif.json
      continue-on-error: true
```
