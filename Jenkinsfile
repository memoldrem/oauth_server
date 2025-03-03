/**
 * Author: Madeline Moldrem
 *
 * This Jenkins pipeline automates the build and deployment process for the OAuth2 server.
 * It performs the following actions:
 *   - Sets an initial GitHub commit status to 'pending' to indicate the build is in progress.
 *   - Checks out the code from GitHub based on the provided branch parameters.
 *   - Generates a unique Docker image tag using the commit hash and branch information.
 *   - Builds the Docker image and conditionally pushes it to Docker Hub.
 *   - Deploys the new Docker image to the target Auto Scaling Group (ASG) for UAT (develop branch) or Prod (master branch)
 *     by SSHing into each instance and running docker-compose commands.
 *   - Updates the GitHub commit status to SUCCESS or FAILURE depending on the final build result.
 *
 * Requirements:
 *   - Proper GitHub credentials with at least the "repo:status" scope.
 *   - Necessary plugins installed (GitHub Plugin, GitHub Commit Status Setter Plugin, etc.).
 *   - AWS CLI configured in Jenkins with permissions to query the ASG and EC2 instances.
 *   - SSH credentials (e.g., 'deployment-credentials') set up in Jenkins for accessing EC2 instances.
 *   - Auto Scaling Groups and ALB set up in your AWS environment.
 */

pipeline {
    agent any

    options {
            // Discard builds older than 14 days or keep only the last 10 builds
            buildDiscarder(logRotator(daysToKeepStr: '14', numToKeepStr: '10'))
        }

    environment {
        DOCKER_REPO = "maddiemoldrem/oauth_server"
        DOCKER_COMPOSE_FILE = "docker-compose.yml"
        GITHUB_REPO = "vineetsingh-vs/oauth2"
        // These should be set either as global Jenkins environment variables or defined here.
        // They represent the ASG names for each environment.
        UAT_ASG_NAME = "maddie-uat-asg"
        PROD_ASG_NAME = "maddie-prod-asg"
    }

    stages {
        // Stage 1: Set GitHub commit status to PENDING.
        stage('Set GitHub Pending Status') {
            steps {
                script {
                    def pendingStatusParams = [
                        statusResultSource: [
                            $class: 'ConditionalStatusResultSource',
                            results: [
                                [$class: 'AnyBuildResult', message: 'Build in progress', state: 'PENDING']
                            ]
                        ]
                    ]
                    step([$class: 'GitHubCommitStatusSetter'] + pendingStatusParams)
                }
            }
        }

        // Stage 2: Checkout the code from GitHub.
        stage('Checkout') {
            steps {
                script {
                    // Remove 'refs/heads/' prefix from WEBHOOK_BRANCH if set.
                    def webhookBranch = env.WEBHOOK_BRANCH?.trim() ? env.WEBHOOK_BRANCH.replaceFirst(/^refs\\/heads\\//, '') : ''
                    def branchToCheckout = webhookBranch ? webhookBranch : (params.BRANCH_BUILD?.trim() ? params.BRANCH_BUILD : 'master')
                    echo "Checking out branch: ${branchToCheckout}"


                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: branchToCheckout]],
                        userRemoteConfigs: [[url: "https://github.com/${env.GITHUB_REPO}.git"]]
                    ])
                     env.BRANCH_NAME = branchToCheckout
                    echo "Checked out branch: ${branchToCheckout}"
                }
            }
        }

        // Stage 3: Set a unique Docker image tag.
        stage('Set Unique Tag') {
            steps {
                script {
                    def commitHash = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    def webhookBranch = env.WEBHOOK_BRANCH?.trim() ? env.WEBHOOK_BRANCH.replaceFirst(/^refs\\/heads\\//, '') : ''
                    def branchUsed = webhookBranch ? webhookBranch : (params.BRANCH_BUILD?.trim() ? params.BRANCH_BUILD : 'master')
                    def sanitizedBranch = branchUsed.replace('/', '-')
                    env.IMAGE_TAG = "${DOCKER_REPO}:${sanitizedBranch}-${env.BUILD_NUMBER}-${commitHash}"
                    echo "Unique Docker Image Tag: ${env.IMAGE_TAG}"
                }
            }
        }

        // Stage 4: Build the Docker image and push it conditionally.
        stage('Build and (Conditionally) Push Docker Image') {
            steps {
                script {
                    echo "Building Docker image with tag ${env.IMAGE_TAG}"
                    sh "docker build --no-cache -t ${env.IMAGE_TAG} ."
                    echo "Docker build completed."

                    def webhookBranch = env.WEBHOOK_BRANCH?.trim() ? env.WEBHOOK_BRANCH.replaceFirst(/^refs\\/heads\\//, '') : ''
                    def effectiveBranch = webhookBranch ? webhookBranch : (params.BRANCH_BUILD?.trim() ? params.BRANCH_BUILD : 'master')
                    def shouldPush = !webhookBranch || (effectiveBranch in ['develop', 'master', 'origin/develop', 'origin/master'])
                    if (shouldPush) {
                        echo "Pushing Docker image for branch: ${effectiveBranch}"
                        withCredentials([usernamePassword(credentialsId: 'maddie-docker', passwordVariable: 'DOCKER_HUB_PASS', usernameVariable: 'DOCKER_HUB_USER')]) {
                            echo "Logging into Docker Hub..."
                            sh "echo ${DOCKER_HUB_PASS} | docker login -u ${DOCKER_HUB_USER} --password-stdin"
                            echo "Docker Hub login succeeded."
                        }
                        sh "docker push ${env.IMAGE_TAG}"
                    } else {
                        echo "Skipping Docker push for branch: ${effectiveBranch}"
                    }
                }
            }
        }

        // Stage 5: Deploy to UAT/Prod via ASG.
        stage('Deploy') {
            when {
                anyOf {
                    branch 'develop'
                    branch 'master'
                    branch 'origin/develop'
                    branch 'origin/master'
                }
            }
            steps {
                script {
                    // Determine target environment based on branch: master -> prod; develop -> uat.
                    def targetEnv = (env.BRANCH_NAME == 'master') ? 'prod' : 'uat'
                    if (params.TARGET_ENV?.trim()) {
                        targetEnv = params.TARGET_ENV.trim()
                    }
                    echo "Target environment: ${targetEnv}"

                    // Determine the ASG name based on environment.
                    def asgName = (targetEnv == 'prod') ? env.PROD_ASG_NAME : env.UAT_ASG_NAME
                    echo "Using ASG: ${asgName}"

                    // Retrieve instance IDs from the ASG using the AWS CLI.
                    def instanceIdsOutput = sh(script: """
                        aws autoscaling describe-auto-scaling-groups \
                          --auto-scaling-group-names ${asgName} \
                          --query "AutoScalingGroups[0].Instances[].InstanceId" \
                          --output text
                    """, returnStdout: true).trim()

                    def instanceIds = instanceIdsOutput.tokenize()
                    echo "Found instances: ${instanceIds}"

                    // Loop through each instance, get its public IP, and deploy.
                    for (instanceId in instanceIds) {
                        def publicIp = sh(script: """
                            aws ec2 describe-instances \
                              --instance-ids ${instanceId} \
                              --query "Reservations[0].Instances[0].PublicIpAddress" \
                              --output text
                        """, returnStdout: true).trim()

                        echo "Deploying to instance ${instanceId} at ${publicIp}"
                        sshagent(['deployment-credentials']) {
                            sh """
                              ssh -o StrictHostKeyChecking=no ubuntu@${publicIp} '
                                  cd /home/ubuntu/deployment/ &&
                                  rm -rf * .[^.]* || true &&
                                  git clone --branch ${env.BRANCH_NAME} https://github.com/${env.GITHUB_REPO}.git . &&
                                  rm -f .env &&
                                  chmod +x variable-env.sh &&
                                  ./variable-env.sh &&
                                  export TARGET_ENV=${targetEnv} &&
                                  export IMAGE_TAG=${env.IMAGE_TAG} &&
                                  docker compose pull &&
                                  docker compose up -d --force-recreate
                              '
                            """
                        }
                    }
                }
            }
        }

        // Stage 6: Set final GitHub commit status.
        stage('Set GitHub Commit Status') {
            steps {
                script {
                    def status = currentBuild.currentResult == 'SUCCESS' ? 'SUCCESS' : 'FAILURE'
                    def message = currentBuild.currentResult == 'SUCCESS' ? 'Build completed successfully' : 'Build failed'
                    def finalStatusParams = [
                        statusResultSource: [
                            $class: 'ConditionalStatusResultSource',
                            results: [
                                [$class: 'AnyBuildResult', message: message, state: status]
                            ]
                        ]
                    ]
                    step([$class: 'GitHubCommitStatusSetter'] + finalStatusParams)
                }
            }
        }
    }

    post {
        always {
            echo "Cleaning up build environment..."
        }
    }
}





