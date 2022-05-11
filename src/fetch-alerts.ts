import { Alert, toAlert } from './entities'
import { Repository } from '@octokit/graphql-schema'
import { getOctokit } from '@actions/github'

export const fetchAlerts = async (
  gitHubPersonalAccessToken: string,
  repositoryName: string,
  repositoryOwner: string,
  count: number,
): Promise<Alert[] | []> => {
  const octokit = getOctokit(gitHubPersonalAccessToken)
  const { repository } = await octokit.graphql<{
    repository: Repository
  }>(`
    query {
      repository(owner:"${repositoryOwner}" name:"${repositoryName}") {
        vulnerabilityAlerts(last: 10000) {
          edges {
            node {
              id
              fixReason            
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
      .filter(o => o.node && o.node.fixReason && o.node.fixReason.length > 1).slice(0,count);
    // console.log('gitHubAlerts', gitHubAlerts);
    // console.log('JSON gitHubAlerts', JSON.stringify(gitHubAlerts));
    const alerts: Alert[] = []
    for (const gitHubAlert of gitHubAlerts) {
      if (gitHubAlert && gitHubAlert.node) {
        alerts.push(toAlert(gitHubAlert.node))
      }
    }
    return alerts
  }
  return []
}
