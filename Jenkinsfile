@Library('acadiaBuildTools@develop') _
import com.vibrenthealth.jenkinsLibrary.Utils
import com.vibrenthealth.jenkinsLibrary.VibrentConstants

def utils = new Utils(this)
def project = "keycloak-operator"
env.PROJECT = project
def label = "${project}-${env.BRANCH_NAME.replaceAll(/\//, "-")}-${env.BUILD_NUMBER}"
def chartDir = "charts/keycloak-operator"
def charts = []
def containers = []
def branch = env.BRANCH_NAME.replace(/\//, '-')

// Only publish the helm chart and image on master branch build
Boolean publishOperator = false

podTemplate(
        cloud: 'default',
        name: label,
        label: label,
        containers: kubeUtils.getCiContainers(containerList: ["kubectl", "docker", "helm", "python"]),
        idleTimeout: 30
) {
    node(label) {
        checkout scm
        chartYaml = readYaml file: "${chartDir}/Chart.yaml"
        if (branch == "master") {
            publishOperator = true

            containers = [
                    ["name": 'vibrent-ops/keycloak-operator',
                     "pushWithBaseTag": false,
                     "additionalPublishTags": ["${chartYaml.version}", "${chartYaml.version}-${utils.getShortCommitSha()}"],
                     "pathToBuildContext": '',
                     "pathToDockerfile": 'Dockerfile']
            ]
        }

        ansiColor('xterm') {
            // NOTE: we use policyIgnoreList to skip docker policy. See README.md for explanation.
            ciPipeline (
                project: env.PROJECT,
                ciImages: containers,
                policyIgnoreList: ["", "build/"],
                checkout: {
                    checkout scm

                    if (publishOperator) {
                        charts << ["chart": "${chartDir}", "version": "${chartYaml.version}", "helmRepo": "vibrent-ops"]
                    }
                },
                charts: {
                    charts
                },
                build: { failableStage ->
                    failableStage('Build') {
                        container('helm') {
                            sh "helm dep build ${chartDir}"
                        }
                        helmUtils.lint(chartsDir: "${chartDir}")
                    }
                },
                unitTest: {},
                sonar: {},
                deploy: {},
                test: {}
            )
        }
    }
}
