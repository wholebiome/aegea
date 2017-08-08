#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function, unicode_literals
import datetime, json, imp
from pprint import pprint

adp = imp.load_source('aegea-deploy-pilot', '/usr/bin/aegea-deploy-pilot')
deployer = imp.load_source('deployer', '/usr/lib/aegea/deployer.py')

# deployment_settings = deployer.gather_deployment_settings()
deployment_settings = {
    "org": "wholebiome",
    "name": "wb_deploy_example",
    "branch": "master"
}
aws_settings = adp.gather_aws_settings()
adp.aws_init(aws_settings, deployment_settings)

print("Topic: {}, (ARN: {})".format(adp.topic_name, adp.topic_arn))

msg = {
    'ref': 'refs/heads/master',
    'commits': [{'added': [],
                 'author': {'email': 'michael.souza@wholebiome.com',
                            'name': 'Michael Souza',
                            'username': 'midnighteuler'},
                 'committer': {'email': 'michael.souza@wholebiome.com',
                               'name': 'Michael Souza',
                               'username': 'midnighteuler'},
                 'distinct': True,
                 'id': '1fec483ea37bdefa051341e64d2b6b29c9ba8188',
                 'message': 'Push message test',
                 'modified': ['Makefile'],
                 'removed': [],
                 'timestamp': '2017-08-04T13:40:55-07:00',
                 'tree_id': '6715bba98441f8a522585d6a6518bcc7a3e4d1b3',
                 'url': 'https://github.com/wholebiome/wb_deploy_example/commit/1fec483ea37bdefa051341e64d2b6b29c9ba8188'}]
}

print("Posting:")
pprint(msg)

client = adp.sns.Topic(adp.topic_arn)
response = client.publish(
    TopicArn=adp.topic_arn,
    Message=json.dumps(msg),
    MessageAttributes={
        'X-Github-Event' : {
            'DataType':'String',
            'StringValue':'push'
        }
    },
    MessageStructure='string'
)
# m.keys:
#   dict_keys(['UnsubscribeURL', 'Signature', 'Type',
#              'Message', 'SigningCertURL', 'MessageAttributes',
#              'SignatureVersion', 'MessageId', 'TopicArn', 'Timestamp'])
# m["Timestamp"]:
#   '2017-08-04T20:39:05.906Z'
# m["Type"]:
#   'Notification'
# m["MessageAttributes"]:
#   {
#     'X-Github-Event' : {
#         'Type':'String',
#         'Value':'push'
#     }
#   },
# m["Message"]:
#     {'after': '1fec483ea37bdefa051341e64d2b6b29c9ba8188',
#      'base_ref': None,
#      'before': 'c7b35a62b019c9c1bf9cb900d7125e5ea667423d',
#      'commits': [{'added': [],
#                   'author': {'email': 'michael.souza@wholebiome.com',
#                              'name': 'Michael Souza',
#                              'username': 'midnighteuler'},
#                   'committer': {'email': 'michael.souza@wholebiome.com',
#                                 'name': 'Michael Souza',
#                                 'username': 'midnighteuler'},
#                   'distinct': True,
#                   'id': '1fec483ea37bdefa051341e64d2b6b29c9ba8188',
#                   'message': 'Push message test',
#                   'modified': ['Makefile'],
#                   'removed': [],
#                   'timestamp': '2017-08-04T13:40:55-07:00',
#                   'tree_id': '6715bba98441f8a522585d6a6518bcc7a3e4d1b3',
#                   'url': 'https://github.com/wholebiome/wb_deploy_example/commit/1fec483ea37bdefa051341e64d2b6b29c9ba8188'}],
#      'compare': 'https://github.com/wholebiome/wb_deploy_example/compare/c7b35a62b019...1fec483ea37b',
#      'created': False,
#      'deleted': False,
#      'forced': False,
#      'head_commit': {'added': [],
#                      'author': {'email': 'michael.souza@wholebiome.com',
#                                 'name': 'Michael Souza',
#                                 'username': 'midnighteuler'},
#                      'committer': {'email': 'michael.souza@wholebiome.com',
#                                    'name': 'Michael Souza',
#                                    'username': 'midnighteuler'},
#                      'distinct': True,
#                      'id': '1fec483ea37bdefa051341e64d2b6b29c9ba8188',
#                      'message': 'Push message test',
#                      'modified': ['Makefile'],
#                      'removed': [],
#                      'timestamp': '2017-08-04T13:40:55-07:00',
#                      'tree_id': '6715bba98441f8a522585d6a6518bcc7a3e4d1b3',
#                      'url': 'https://github.com/wholebiome/wb_deploy_example/commit/1fec483ea37bdefa051341e64d2b6b29c9ba8188'},
#      'organization': {'avatar_url': 'https://avatars3.githubusercontent.com/u/18098328?v=4',
#                       'description': '',
#                       'events_url': 'https://api.github.com/orgs/wholebiome/events',
#                       'hooks_url': 'https://api.github.com/orgs/wholebiome/hooks',
#                       'id': 18098328,
#                       'issues_url': 'https://api.github.com/orgs/wholebiome/issues',
#                       'login': 'wholebiome',
#                       'members_url': 'https://api.github.com/orgs/wholebiome/members{/member}',
#                       'public_members_url': 'https://api.github.com/orgs/wholebiome/public_members{/member}',
#                       'repos_url': 'https://api.github.com/orgs/wholebiome/repos',
#                       'url': 'https://api.github.com/orgs/wholebiome'},
#      'pusher': {'email': 'mike@michaelsouza.com', 'name': 'midnighteuler'},
#      'ref': 'refs/heads/master',
#      'repository': {'archive_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/{archive_format}{/ref}',
#                     'assignees_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/assignees{/user}',
#                     'blobs_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/git/blobs{/sha}',
#                     'branches_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/branches{/branch}',
#                     'clone_url': 'https://github.com/wholebiome/wb_deploy_example.git',
#                     'collaborators_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/collaborators{/collaborator}',
#                     'comments_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/comments{/number}',
#                     'commits_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/commits{/sha}',
#                     'compare_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/compare/{base}...{head}',
#                     'contents_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/contents/{+path}',
#                     'contributors_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/contributors',
#                     'created_at': 1501106071,
#                     'default_branch': 'master',
#                     'deployments_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/deployments',
#                     'description': None,
#                     'downloads_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/downloads',
#                     'events_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/events',
#                     'fork': False,
#                     'forks': 0,
#                     'forks_count': 0,
#                     'forks_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/forks',
#                     'full_name': 'wholebiome/wb_deploy_example',
#                     'git_commits_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/git/commits{/sha}',
#                     'git_refs_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/git/refs{/sha}',
#                     'git_tags_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/git/tags{/sha}',
#                     'git_url': 'git://github.com/wholebiome/wb_deploy_example.git',
#                     'has_downloads': True,
#                     'has_issues': True,
#                     'has_pages': False,
#                     'has_projects': True,
#                     'has_wiki': True,
#                     'homepage': None,
#                     'hooks_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/hooks',
#                     'html_url': 'https://github.com/wholebiome/wb_deploy_example',
#                     'id': 98468889,
#                     'issue_comment_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/issues/comments{/number}',
#                     'issue_events_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/issues/events{/number}',
#                     'issues_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/issues{/number}',
#                     'keys_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/keys{/key_id}',
#                     'labels_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/labels{/name}',
#                     'language': 'Makefile',
#                     'languages_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/languages',
#                     'master_branch': 'master',
#                     'merges_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/merges',
#                     'milestones_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/milestones{/number}',
#                     'mirror_url': None,
#                     'name': 'wb_deploy_example',
#                     'notifications_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/notifications{?since,all,participating}',
#                     'open_issues': 0,
#                     'open_issues_count': 0,
#                     'organization': 'wholebiome',
#                     'owner': {'avatar_url': 'https://avatars3.githubusercontent.com/u/18098328?v=4',
#                               'email': '',
#                               'events_url': 'https://api.github.com/users/wholebiome/events{/privacy}',
#                               'followers_url': 'https://api.github.com/users/wholebiome/followers',
#                               'following_url': 'https://api.github.com/users/wholebiome/following{/other_user}',
#                               'gists_url': 'https://api.github.com/users/wholebiome/gists{/gist_id}',
#                               'gravatar_id': '',
#                               'html_url': 'https://github.com/wholebiome',
#                               'id': 18098328,
#                               'login': 'wholebiome',
#                               'name': 'wholebiome',
#                               'organizations_url': 'https://api.github.com/users/wholebiome/orgs',
#                               'received_events_url': 'https://api.github.com/users/wholebiome/received_events',
#                               'repos_url': 'https://api.github.com/users/wholebiome/repos',
#                               'site_admin': False,
#                               'starred_url': 'https://api.github.com/users/wholebiome/starred{/owner}{/repo}',
#                               'subscriptions_url': 'https://api.github.com/users/wholebiome/subscriptions',
#                               'type': 'Organization',
#                               'url': 'https://api.github.com/users/wholebiome'},
#                     'private': True,
#                     'pulls_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/pulls{/number}',
#                     'pushed_at': 1501879145,
#                     'releases_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/releases{/id}',
#                     'size': 2,
#                     'ssh_url': 'git@github.com:wholebiome/wb_deploy_example.git',
#                     'stargazers': 0,
#                     'stargazers_count': 0,
#                     'stargazers_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/stargazers',
#                     'statuses_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/statuses/{sha}',
#                     'subscribers_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/subscribers',
#                     'subscription_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/subscription',
#                     'svn_url': 'https://github.com/wholebiome/wb_deploy_example',
#                     'tags_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/tags',
#                     'teams_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/teams',
#                     'trees_url': 'https://api.github.com/repos/wholebiome/wb_deploy_example/git/trees{/sha}',
#                     'updated_at': '2017-07-26T21:55:25Z',
#                     'url': 'https://github.com/wholebiome/wb_deploy_example',
#                     'watchers': 0,
#                     'watchers_count': 0},
#      'sender': {'avatar_url': 'https://avatars2.githubusercontent.com/u/6269913?v=4',
#                 'events_url': 'https://api.github.com/users/midnighteuler/events{/privacy}',
#                 'followers_url': 'https://api.github.com/users/midnighteuler/followers',
#                 'following_url': 'https://api.github.com/users/midnighteuler/following{/other_user}',
#                 'gists_url': 'https://api.github.com/users/midnighteuler/gists{/gist_id}',
#                 'gravatar_id': '',
#                 'html_url': 'https://github.com/midnighteuler',
#                 'id': 6269913,
#                 'login': 'midnighteuler',
#                 'organizations_url': 'https://api.github.com/users/midnighteuler/orgs',
#                 'received_events_url': 'https://api.github.com/users/midnighteuler/received_events',
#                 'repos_url': 'https://api.github.com/users/midnighteuler/repos',
#                 'site_admin': False,
#                 'starred_url': 'https://api.github.com/users/midnighteuler/starred{/owner}{/repo}',
#                 'subscriptions_url': 'https://api.github.com/users/midnighteuler/subscriptions',
#                 'type': 'User',
#                 'url': 'https://api.github.com/users/midnighteuler'}}