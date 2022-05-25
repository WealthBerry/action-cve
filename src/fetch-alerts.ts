import { Alert, toAlert } from './entities'
import { Repository } from '@octokit/graphql-schema'
import { getOctokit } from '@actions/github'
import JiraApi from 'jira-client'


async function registerIssue(summary: string, description: string, siembot_jira_user: string, siembot_jira_pass: string) {
  return new Promise((resolve, reject) => {

    const jira = new JiraApi({
      protocol: 'https',
      host: 'wealthberry.atlassian.net',
      username: siembot_jira_user,
      password: siembot_jira_pass,
      apiVersion: '2',
      strictSSL: true,
    });

    jira.searchJira('project = "WBP" AND summary ~ "' + summary + '" ORDER BY updated DESC')
      .then((data) => {
        if (data.issues && data.issues.length > 0) {
          console.log('Already exists');
          resolve(false);
        } else {
          jira.addNewIssue({
            fields: {
              summary: summary,
              issuetype: {
                name: "Task"
              },
	      priority: {
                name: "Highest"
	      },
              labels: [
                "siem"
              ],
              project: {
                "id": "10000"
              },
              "description": description,
            }
          }).then((data) => {
            console.log(data);
            resolve(true);
          });
        }
      });
  });

}

export const fetchAlerts = async (
  gitHubPersonalAccessToken: string,
  repositoryName: string,
  repositoryOwner: string,
  count: number,
  siembot_jira_user: string,
  siembot_jira_pass: string
): Promise<Alert[] | []> => {
  const octokit = getOctokit(gitHubPersonalAccessToken)
  const { repository } = await octokit.graphql<{
    repository: Repository
  }>(`
    query {
      repository(owner:"${repositoryOwner}" name:"${repositoryName}") {
        vulnerabilityAlerts(last: 100) {
          edges {
            node {
              id
              fixReason            
              dismissReason
              repository {
                name
                owner {
                  login
                }
              }
              securityAdvisory {
                id
                description
                cvss {
                  score
                  vectorString
                }
                permalink
                severity
                summary
              }
              securityVulnerability {
                firstPatchedVersion {
                  identifier
                }
                package {
                  ecosystem
                  name
                }
                vulnerableVersionRange
                advisory {
                  cvss {
                    score
                    vectorString
                  }
                  summary
                }
              }
            }
          }
        }
      }
    }
  `)
  let gitHubAlerts = repository.vulnerabilityAlerts?.edges as Array<any>;
  if (gitHubAlerts) {
    gitHubAlerts = gitHubAlerts
      .filter(o => o.node && !o.node.fixReason).slice(0,count);
    console.log('gitHubAlerts', gitHubAlerts);
    console.log('JSON gitHubAlerts', JSON.stringify(gitHubAlerts));
    const alerts: Alert[] = []
    for (const gitHubAlert of gitHubAlerts) {
      if (gitHubAlert && gitHubAlert.node && gitHubAlert.node.securityAdvisory) {
        const res = await registerIssue(
          "siem-bot-github-issue-" + gitHubAlert.node.securityAdvisory.id,
          gitHubAlert.node.securityAdvisory.description + '\n\n' + JSON.stringify(gitHubAlert),
          siembot_jira_user,
          siembot_jira_pass
      );
        if (res === true) alerts.push(toAlert(gitHubAlert.node))
      }
    }
    return alerts
  }
  return []
}
