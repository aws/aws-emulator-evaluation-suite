"""project-delete-sibling-survives-batch-get-partition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


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
    import json

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_project(cb, ctx, *, service_role):
    """Create a uniquely-named NO_SOURCE project with the given service role (retry through IAM propagation)."""
    name = ctx.unique_name("sim2real-behav-proj-")
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
        "serviceRole": service_role,
        "tags": [{"key": "sim2real", "value": CHECK}],
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


CHECK = "project-delete-sibling-survives-batch-get-partition"
GROUP = 'project'
SERVICES = ['codebuild', 'iam']


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProject empties its body, drops the deleted project from a paginated ListProjects
    while a sibling stays, BatchGetProjects partitions the two accordingly, and repeating the
    delete on the now-absent name again succeeds with an empty body.
    """
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    kept = _create_project(cb, ctx, service_role=role)
    doomed = _create_project(cb, ctx, service_role=role)
    kept_name = kept["name"]
    doomed_name = doomed["name"]

    first = cb.delete_project(name=doomed_name)
    extra_first = {k: v for k, v in first.items() if k != "ResponseMetadata"}
    assert extra_first == {}, f"expected an empty DeleteProject body, got {first!r}"

    def _names():
        names = set()
        paginator = cb.get_paginator("list_projects")
        for page in paginator.paginate():
            names.update(page.get("projects", []))
        return names

    remaining = _poll_until(
        _names,
        lambda n: doomed_name not in n and kept_name in n,
        timeout_s=30,
        interval_s=2,
        description="deleted project absent from ListProjects while its sibling remains",
    )
    assert doomed_name not in remaining, f"expected {doomed_name!r} absent, got {remaining!r}"
    assert kept_name in remaining, f"expected sibling {kept_name!r} still listed, got {remaining!r}"

    batch = cb.batch_get_projects(names=[doomed_name, kept_name])
    materialized = {p["name"] for p in batch.get("projects", [])}
    not_found = set(batch.get("projectsNotFound", []))
    assert materialized == {kept_name}, f"expected only {kept_name!r} in projects, got {materialized!r}"
    assert not_found == {doomed_name}, f"expected only {doomed_name!r} in projectsNotFound, got {not_found!r}"

    second = cb.delete_project(name=doomed_name)
    extra_second = {k: v for k, v in second.items() if k != "ResponseMetadata"}
    assert extra_second == {}, (
        f"expected a repeated DeleteProject on the already-deleted name to again return an "
        f"empty body, got {second!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
