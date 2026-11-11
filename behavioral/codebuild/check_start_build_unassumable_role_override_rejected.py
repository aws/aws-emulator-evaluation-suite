"""start-build-unassumable-role-override-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


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
    """Delete an IAM role, removing its inline policies first (cleanup path: best-effort)."""
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
    """Mint a real CodeBuild-assumable IAM service role so CreateProject validates. Returns its ARN."""
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


_BUILDSPEC_NOOP = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo sim2real-noop\n"
)

# NO cache, NO artifacts, both log destinations DISABLED: a project in this shape leaves
# behind no S3 object, no cache bucket and no /aws/codebuild/<project> log group, so the
# only resource to reclaim is the project itself.
_NO_LOGS = {
    "cloudWatchLogs": {"status": "DISABLED"},
    "s3Logs": {"status": "DISABLED"},
}


def _project_args(name, role, **over):
    """Minimal-cost valid CreateProject kwargs: NO_SOURCE + inline buildspec, NO_ARTIFACTS,
    LINUX_CONTAINER / BUILD_GENERAL1_SMALL (never ARM/LARGE/GPU), logs off, no vpcConfig."""
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
    args.update(over)
    return args


def _create_project(cb, ctx, name, role, **over):
    """CreateProject, retrying through IAM trust-policy propagation; registers teardown
    immediately on success. Returns the project dict."""
    deadline = time.monotonic() + 90
    while True:
        try:
            proj = cb.create_project(**_project_args(name, role, **over))["project"]
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

CHECK = "start-build-unassumable-role-override-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuild MUST refuse a serviceRoleOverride that CodeBuild cannot assume, start NO
    build, and leave the project's own serviceRole untouched."""
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")
    proj = _create_project(cb, ctx, name, role)
    account = proj["arn"].split(":")[4]
    bad_role = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-missing-role-')}"

    # Register the stop BEFORE the call, so an over-permissive emulator that actually starts
    # a build does not leave it billing for its full timeoutInMinutes.
    holder = {"id": None}

    def _stop():
        if holder["id"]:
            try:
                cb.stop_build(id=holder["id"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_stop)

    def _start():
        resp = cb.start_build(projectName=name, serviceRoleOverride=bad_role)
        holder["id"] = resp["build"]["id"]
        return resp

    code, message = _client_error(_start)
    assert code == "InvalidInputException", (
        f"StartBuild rejected the unassumable serviceRoleOverride with code={code!r}; "
        f"started build id={holder['id']!r}"
    )
    expected = (
        "CodeBuild is not authorized to perform: sts:AssumeRole on service role. Please verify "
        "that: 1) The provided service role exists, 2) The role name is case-sensitive and "
        "matches exactly, and 3) The role has the necessary trust policy configured."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the project has no builds at all.
    listed = cb.list_builds_for_project(projectName=name)
    assert listed.get("ids") == [], (
        f"a rejected StartBuild must leave the project with zero builds, got {listed.get('ids')}"
    )

    # Control: the project itself is intact and still carries its original service role.
    got = cb.batch_get_projects(names=[name])
    assert got.get("projectsNotFound", []) == [], got
    assert len(got.get("projects", [])) == 1, got
    assert got["projects"][0]["serviceRole"] == role, (
        f"the rejected override must not mutate the project's serviceRole: "
        f"{got['projects'][0]['serviceRole']!r} != {role!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
