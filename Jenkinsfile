pipeline {
  agent any
  options { timestamps() }
  stages {
    stage('Setup')   { steps { sh 'python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt' } }
    stage('Lint')    { steps { sh '. .venv/bin/activate && yamllint -d relaxed topology ansible' } }
    stage('Policy')  { steps { sh '. .venv/bin/activate && python tools/check_policy.py' } }
    stage('Compose') { steps { sh 'docker compose config -q' } }
    stage('E2E (Namespaces)') {
      steps { sh 'sudo -n .venv/bin/python tools/netns_test.py' }
    }
    stage('Ansible Syntax') { steps { sh '. .venv/bin/activate && cd ansible && ansible-playbook site.yml --syntax-check' } }
  }
  post { always { archiveArtifacts artifacts: 'build/fw/nftables.conf,build/policy.json', allowEmptyArchive: true } }
}
