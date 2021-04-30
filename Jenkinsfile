@Library('acadiaBuildTools@feature/harbor') _

import com.vibrenthealth.jenkinsLibrary.VibrentConstants

def project = "keycloak-operator"
env.PROJECT = project
def label = "${project}-${env.BRANCH_NAME.replaceAll(/\//, "-")}-${env.BUILD_NUMBER}"
def chartDir = "charts/keycloak-operator"
def charts = []
def containers = []
def branch = env.BRANCH_NAME.replace(/\//, '-')

// Only publish the helm chart and image on mergew to master
Boolean publishOperator = false
//if (branch == "master") {
    publishOperator = true
  
    containers = [
        ["name": 'vibrent/keycloak-operator', "pathToBuildContext": '', "pathToDockerfile": 'Dockerfile']
    ]
//}

podTemplate(
        cloud: 'default',
        name: label,
        label: label,
        containers: kubeUtils.getCiContainers(containerList: ["kubectl", "docker", "helm", "python"]),
        volumes: [hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock')],
        idleTimeout: 30
) {
    node(label) {
        def stackNameRegex = "[^A-Za-z0-9-]"
        def stackName = "${env.PROJECT}-${branch}-${env.BUILD_NUMBER}".replaceAll(/(feature-|release-)/, "").replaceAll(stackNameRegex, "-").toLowerCase().take(60)
        
        ansiColor('xterm') {
            ciPipeline (
                project: env.PROJECT,
                ciImages: containers,
                checkout: {
                    checkout scm

                    if (publishOperator) {
                        chartYaml = readYaml file: "${chartDir}/Chart.yaml"
                        charts << ["chart": "${chartDir}", "version": "${chartYaml.version}", "helmRepo": "vibrent"]
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
