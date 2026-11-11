"""batch-get-projects-absent-projects-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


def _delete_role(iam, role_name):
    """Delete an IAM role, detaching its inline policies first (best-effort)."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx):
    """Mint a real CodeBuild-assumable IAM service role (so CreateProject validates); return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": "batch-get-projects-absent-projects-not-found"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            }],
        }),
    )
    return resp["Role"]["Arn"]


def _create_project(cb, ctx):
    """Create a uniquely-named TEST project with a real service role (retry through IAM propagation)."""
    name = ctx.unique_name("sim2real-behav-proj-")
    role = _create_service_role(ctx)
    kwargs = {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role,
        "tags": [{"key": "sim2real", "value": "batch-get-projects-absent-projects-not-found"}],
    }
    deadline = time.monotonic() + 75
    while True:
        try:
            resp = cb.create_project(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    proj = resp["project"]
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


# ===== check =====

CHECK = "batch-get-projects-absent-projects-not-found"
GROUP = 'lifecycle'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetProjects reports an absent project in projectsNotFound (no exception) and never in
    projects, while a real project requested in the same call is returned."""
    cb = ctx.client("codebuild")
    proj = _create_project(cb, ctx)
    real_name = proj["name"]
    absent_name = ctx.unique_name("sim2real-behav-missing-proj-")

    resp = cb.batch_get_projects(names=[real_name, absent_name])
    materialized = {p["name"] for p in resp.get("projects", [])}
    not_found = set(resp.get("projectsNotFound", []))

    assert absent_name in not_found, resp
    assert absent_name not in materialized, resp
    assert real_name in materialized, resp
    assert real_name not in not_found, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
