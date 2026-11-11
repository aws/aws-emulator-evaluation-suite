"""start-build-absent-project-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_role(iam, role_name):
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


_BUILDSPEC_NOOP = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo sim2real-noop\n"
)

_NO_LOGS = {
    "cloudWatchLogs": {"status": "DISABLED"},
    "s3Logs": {"status": "DISABLED"},
}


def _create_project(cb, ctx, name, role):
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": _BUILDSPEC_NOOP},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role,
        "logsConfig": dict(_NO_LOGS),
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    deadline = time.monotonic() + 90
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


# ===== check =====

CHECK = "start-build-absent-project-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuild on a nonexistent project fails with ResourceNotFoundException and starts nothing, while
    the identical call on a real project starts a build that ListBuildsForProject returns."""
    cb = ctx.client("codebuild")

    missing = ctx.unique_name("sim2real-behav-missing-proj-")
    code, message = _client_error(lambda: cb.start_build(projectName=missing))
    assert code == "ResourceNotFoundException", code
    expected = f"Project cannot be found: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{missing}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the identical call against a real project must succeed.
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")
    _create_project(cb, ctx, name, role)

    holder = {"id": None}

    def _stop():
        if holder["id"]:
            try:
                cb.stop_build(id=holder["id"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_stop)

    resp = cb.start_build(projectName=name)
    holder["id"] = resp["build"]["id"]

    # Independent read at the destination: the build the positive control started is now
    # visible under the project, through a different operation than the one that started it.
    listed = cb.list_builds_for_project(projectName=name)
    assert holder["id"] in listed.get("ids", []), (
        f"StartBuild against a real project succeeded but the build is not listed: {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
