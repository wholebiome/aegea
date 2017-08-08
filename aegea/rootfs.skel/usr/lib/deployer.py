#!/usr/bin/env python3

"""Usage:
      deployer.py [-hd] [--make <target>] [--make-reload <reload-target>]
      [--deploy-location <dep-loc>] [--deploy-key-name <dep-key>]
      (setup|deploy|ls)
      [<repo-org> <repo-name> <repo-branch>]

Options:
      -h --help                          This message
      -d --debug                         Debug logging
      -m, --make <target>                Makefile target to build deployment [Default: ]
      -r, --make-reload <reload-target>  Makefile target to reload deployment [Default: reload]
      -e, --deploy-location <dep-loc>    Base directory deployments build within [Default: /opt]
      -k, --deploy-key-name <dep-key>    Aegea secret key name. Default is "deploy.<repo-org>.<repo-name>"
      <repo-org>                         Organization of repository
      <repo-name>                        Repository to deploy
      <repo-branch>                      Branch to deploy [Default: master]

Commands:
      setup     Setup deployment on this machine
      deploy    Manually invoke deployment on this machine
      ls        List deployments set up on this machine

Examples:
      deployer.py setup wholebiome akita
      deployer.py -d --make custom_target deploy wholebiome wb_deploy_example branchtest
      deployer.py ls
"""
# Note: The functions within the "Deployment launching" section
#       are imported and used by aegea-deploy-pilot.

from __future__ import absolute_import, division, print_function, unicode_literals
import os, sys, subprocess, json, logging, argparse, shutil, signal
from datetime import datetime
import dateutil.parser
import shutil

SERVICES_DIR     = "/etc/systemd/system/multi-user.target.wants"
SERVICE_TEMPLATE = "/lib/systemd/system/aegea-deploy@.service"

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

def gather_deployment_settings(**kwargs):
    global deployment_settings

    settings = {
        "org": os.environ.get("REPOORG"),
        "name": os.environ.get("REPONAME"),
        "branch": os.environ.get("REPOBRANCH") or "master",
        "make_target": os.environ.get("MAKETARGET"),
        "make_reload_target": os.environ.get("MAKERELOADTARGET"),
        "deploy_location": os.environ.get("DEPLOY_LOCATION") or "/opt",
        "deploy_key_name": os.environ.get("DEPLOY_KEY_NAME"),
        "github_url": None
    }

    settings = dict(settings, **kwargs)

    if settings["org"] is not None and settings["name"] is not None:
        settings["github_url"] = "git@github.com:{}/{}".format(settings["org"], settings["name"])
        if settings["deploy_key_name"] is None:
            settings["deploy_key_name"] = "deploy.{}.{}".format(settings["org"], settings["name"])

    deployment_settings = settings

    return deployment_settings

####
# Deployment setup.
#
# This reads the file at SERVICE_TEMPLATE ("aegea-deploy@.service")
# string substitutes the deployment settings into it,
# writes it into the folder watched by systemd,
# then tells systemd to scan for changes.
####

def print_service_help(deploy):
    log.info("----------------------------")
    log.info("")
    log.info(" Start/stop service with:")
    log.info("  service {} stop".format(deploy))
    log.info("  service {} start".format(deploy))
    log.info("  service {} status".format(deploy))
    log.info("")
    log.info("----------------------------")

def setup_deployment(deployment_settings):
    deploy = "aegea-deploy@{o}-{n}-{b}".format(o=deployment_settings["org"],
                                               n=deployment_settings["name"],
                                               b=deployment_settings["branch"])
    output_to = "{servicesDir}/{deploy}.service".format(servicesDir=SERVICES_DIR,
                                                       deploy=deploy)

    # Read service template, substitute customizations into env vars
    s = open(SERVICE_TEMPLATE, 'r').read() \
        .format(makeTarget=deployment_settings["make_target"],
                makeReloadTarget=deployment_settings["make_reload_target"],
                repoOrg=deployment_settings["org"],
                repoName=deployment_settings["name"],
                repoBranch=deployment_settings["branch"])

    # Write as service file to the servicesDir
    o = open(output_to, "w")
    o.write(s)
    o.close()
    subprocess.call("systemctl daemon-reload", shell=True)
    log.info(s)

    log.info("Wrote service to {}".format(output_to))
    print_service_help(deploy)

def ls(deployment_settings):
    cmd = "tree -P \"*aegea*\" {}".format(SERVICES_DIR)
    log.info("Deployments: \n{}".format(cmd))
    log.info("----------------------------")
    subprocess.call(cmd, shell=True)
    print_service_help("aegea-deploy@org-repo-branch")

    cmd = "tree -L 5 -P builds -I source {}".format(deployment_settings["deploy_location"])
    log.info("Builds: \n{}".format(cmd))
    log.info("----------------------------")
    subprocess.call(cmd, shell=True)

####
# Deployment launching.
#
####
def run_git_command(*cmd, **kwargs):
    kwargs["env"] = dict(kwargs.get("env", os.environ), GIT_SSH_COMMAND="aegea-git-ssh-helper")
    return subprocess.check_call(["git"] + list(cmd), **kwargs)

def get_git_command_output(*cmd, **kwargs):
    kwargs["env"] = dict(kwargs.get("env", os.environ), GIT_SSH_COMMAND="aegea-git-ssh-helper")
    return subprocess.check_output(["git"] + list(cmd), **kwargs).decode().strip()

def get_deploy_rev(deployment_settings):
    try:
        cmd = ["git", "rev-parse", "--short", "HEAD"]
        return subprocess.check_output(cmd, cwd=deployment_settings["deploy_location"]).decode().strip()
    except Exception:
        return "Unknown"

def get_deploy_desc(deployment_settings):
    try:
        cmd = ["git", "describe", "--always", "--all"]
        return subprocess.check_output(cmd, cwd=deployment_settings["deploy_location"]).decode().strip()
    except Exception:
        return "Unknown"

def clone_and_build(deployment_settings, commit_id="latest"):
    branch = deployment_settings["branch"]
    github_url = deployment_settings["github_url"]
    make_target = deployment_settings["make_target"]
    make_reload_target = deployment_settings["make_target"]

    org = deployment_settings["org"]
    name = deployment_settings["name"]
    branch = deployment_settings["branch"]

    # Github doesn't allow single git revision clones: https://github.com/isaacs/github/issues/436
    # We can use "uploadpack.allowReachableSHA1InWant" locally to clone individual revisions
    # from repo_base_dir, which contains a minimally sufficient fetched refs from remote origin
    # for any branches deployed.
    # deployment_settings["deploy_location"] = '/home/mlsouza/Desktop/tmp/git_test'
    repo_base_dir = os.path.join(deployment_settings["deploy_location"], org, name, "source")
    branch_dir = os.path.join(deployment_settings["deploy_location"], org, name, "builds", branch)

    if not os.path.exists(repo_base_dir):
        log.info("Creating base repo dir: {}".format(repo_base_dir))
        os.makedirs(repo_base_dir)
        log.info("Setting github origin url: {}".format(github_url))
        run_git_command("init", repo_base_dir)
        run_git_command("remote", "add", "origin", github_url, cwd=repo_base_dir)
        # https://git-scm.com/docs/git-config

        run_git_command("config", "uploadpack.allowReachableSHA1InWant", "true", cwd=repo_base_dir)

    if not os.path.exists(branch_dir):
        # For "latest" we only need the commit on the top.
        # Note that this means subsequent fetches will only get after this point.
        # (Deployment daemons assumed to only deploy commits happening after the time
        # of initial launch.)
        if commit_id == "latest":
            run_git_command("fetch", "--recurse-submodules", "origin", branch, "--depth=1", cwd=repo_base_dir)
            run_git_command("checkout", "--track", "origin/{}".format(branch), cwd=repo_base_dir)

    # Fetch any updates for branch.
    run_git_command("fetch", "--recurse-submodules", "origin", branch,  cwd=repo_base_dir)

    # Check out commit from updated local source.
    stage_dir = os.path.join(branch_dir, datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    run_git_command("init", stage_dir)
    run_git_command("remote", "add", "origin", repo_base_dir, cwd=stage_dir)
    if commit_id == "latest":
        run_git_command("pull", "--recurse-submodules", "origin", branch, "--depth=1", cwd=stage_dir)
    else:
        run_git_command("pull", "--recurse-submodules", "origin", commit_id, "--depth=1", cwd=stage_dir)
    commit_id = get_git_command_output("rev-parse", "--short", "HEAD", cwd=stage_dir)

    # Use commit hash as folder name
    deploy_dir = os.path.join(deployment_settings["deploy_location"], org, name, "builds", branch, commit_id)
    if os.path.exists(deploy_dir):
        shutil.rmtree(deploy_dir)
    os.rename(stage_dir, deploy_dir)

    log.info("Deploying %s (%s) to %s", deployment_settings["branch"], commit_id, deploy_dir)
    subprocess.check_call(["make", "-C", deploy_dir] + ([make_target] if make_target else []))
    subprocess.check_call(["make", "-C", deploy_dir, make_reload_target if make_reload_target else "reload"])

def clean_old_builds(build_root, prefix, min_old_builds=2):
    build_dirs = [os.path.join(build_root, d) for d in os.listdir(build_root) if d.startswith(prefix)]
    build_dirs = [d for d in build_dirs if os.path.isdir(d) and not os.path.islink(d)]
    build_dirs = sorted(build_dirs, key=lambda d: os.stat(d).st_mtime)
    for d in build_dirs[:-min_old_builds]:
        logging.warn("Deleting old build %s", d)
        shutil.rmtree(d, ignore_errors=True)

def deploy(deployment_settings, commit_id="latest"):
    clone_and_build(deployment_settings, commit_id)

    # build_root, prefix, min_old_builds=2
    # clean_old_builds(os.path.dirname(deployment_settings["deploy_location"]), prefix=deployment_settings["name"] + "-")

def handle_github_messages(messages):
    if len(messages) == 0:
        return

    # Github broadcasts events on the repo level to the SNS topic
    # and the SQS queue receiving those messages isn't necessarily in FIFO temporal order.
    # http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-how-it-works.html
    #
    # I.e. "messages" is an array of (possibly unordered) github events (not necessarily "push")
    # for any branch in the repo.
    #
    # We filter for events that are for this branch and are "push" events
    # and then take the most recent to deploy.
    # https://developer.github.com/v3/activity/events/types/

    HANDLED_EVENT_TYPES = ["push"]
    latest_message = None
    for message in messages:
        m = json.loads(message.body)

        event_type = None
        if "MessageAttributes" in m and "X-Github-Event" in m["MessageAttributes"]:
            event_type = m["MessageAttributes"]["X-Github-Event"]["Value"]

        if event_type is None:
            log.info("Discarding received event with unknown structure:")
            log.info(m)
            continue

        if event_type not in HANDLED_EVENT_TYPES:
            log.info("Discarding github event not in handled types. ({})"
                         .format(HANDLED_EVENT_TYPES))
            log.info(m)
            continue

        event = json.loads(m["Message"])
        our_branch_ref = "refs/heads/" + deployment_settings["branch"]
        if event["ref"] != our_branch_ref:
            log.info("Discarding github event for other branch (We are: {}, got event for: {})"
                         .format(our_branch_ref, event["ref"]))
            log.info(m)
            continue

        # We want the latest event.
        if latest_message is None:
            latest_message = m
            continue
        lt = dateutil.parser.parse(latest_message["Timestamp"])
        mt = dateutil.parser.parse(m["Timestamp"])
        if mt > lt:
            log.info("Discarding non-recent github event")
            log.info(m)
            latest_message = m
            continue

    if latest_message is None:
        log.info("All messages in provided set were discarded.")
        return

    latest_message = json.loads(latest_message["Message"])
    log.info("Deploying using github event:")
    log.info(latest_message)

    # Deploy the latest event.
    # Pushes can have multiple commits; we want the latest of those.
    latest_commit = latest_message["commits"][0]
    for commit in latest_message["commits"][1:]:
        lt = dateutil.parser.parse(latest_commit["timestamp"])
        ct = dateutil.parser.parse(commit["timestamp"])
        if ct > lt:
            log.info("Skipping older commit at {}: \"{}\" ({})".format(
                commit["timestamp"],
                commit["message"],
                commit["id"]))
            latest_commit = commit

    log.info("Deploying commit:")
    log.info(latest_commit)

    deploy(deployment_settings=deployment_settings,
           commit_id=latest_commit["id"])

if __name__ == "__main__":
    import docopt
    from docopt import DocoptExit

    def _require_org_and_name():
        if deployment_settings["org"] is None \
                or deployment_settings["name"] is None:
            logging.error("Repository organization and name required")
            raise DocoptExit()

    args = docopt.docopt(__doc__, options_first=True)
    debug = "--debug" if args['--debug'] else ''
    log.setLevel((logging.DEBUG if debug else logging.INFO))
    log.debug("Received arguments: {}".format(args))

    gather_deployment_settings(org=args["<repo-org>"],
                               name=args["<repo-name>"],
                               branch=args["<repo-branch>"] or "master",
                               make_target=args["--make"],
                               make_reload_target=args["--make-reload"],
                               deploy_location=args["--deploy-location"],
                               deploy_key=args["--deploy-key-name"])
    log.debug("Deployment settings: {}".format(deployment_settings))

    if args["setup"]:
        _require_org_and_name()
        setup_deployment(deployment_settings)
    elif args['deploy']:
        _require_org_and_name()
        deploy(deployment_settings)
    elif args['ls']:
        ls(deployment_settings)