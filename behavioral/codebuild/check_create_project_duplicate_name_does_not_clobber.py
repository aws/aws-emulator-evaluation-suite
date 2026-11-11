"""create-project-duplicate-name-does-not-clobber."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags



def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    }
    args.update(over)
    return args


def _is_transient_role_error(err):
    """True for an InvalidInputException caused by IAM trust-policy propagation lag,
    which is retryable, as opposed to any other InvalidInputException, which is not."""
    msg = (err.get("Message") or "").lower()
    return err.get("Code") == "InvalidInputException" and (
        "assume" in msg or "not authorized" in msg
    )


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
            if _is_transient_role_error(err) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj



CHECK = "create-project-duplicate-name-does-not-clobber"
GROUP = 'project'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateProject with an existing name MUST raise ResourceAlreadyExistsException
    and MUST NOT overwrite any field of the existing project; an upsert silently discards config.
    """
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")

    # The second call carries a different description and timeout, so a clobber is observable.
    original = _create_project(cb, ctx, name, role,
                               description="sim2real original", timeoutInMinutes=30)
    assert original["description"] == "sim2real original", original
    assert original["timeoutInMinutes"] == 30, original

    # Retry through IAM trust propagation so a transient InvalidInputException is not read as
    # the duplicate-name verdict.
    def _create_again():
        deadline = time.monotonic() + 90
        while True:
            try:
                return cb.create_project(**_project_args(
                    name, role, description="sim2real clobbered", timeoutInMinutes=45))
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if _is_transient_role_error(err) and time.monotonic() < deadline:
                    time.sleep(3)
                    continue
                raise

    code, message = _error(_create_again)
    assert (code, message) == (
        "ResourceAlreadyExistsException",
        f"Project already exists: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{name}",
    ), (code, message)

    # Effect absent (no clobber): every field of the live project is the original one.
    got = cb.batch_get_projects(names=[name])
    assert len(got.get("projects", [])) == 1, got
    live = got["projects"][0]
    assert live["description"] == "sim2real original", (
        f"the rejected duplicate clobbered description: {live['description']!r}"
    )
    assert live["timeoutInMinutes"] == 30, (
        f"the rejected duplicate clobbered timeoutInMinutes: {live['timeoutInMinutes']!r}"
    )
    assert live["arn"] == original["arn"], (live["arn"], original["arn"])

    # Control: the same body under a fresh name is accepted, so the refusal was about the
    # name collision and not about the payload.
    other = ctx.unique_name("sim2real-behav-proj-")
    fresh = _create_project(cb, ctx, other, role,
                            description="sim2real clobbered", timeoutInMinutes=45)
    assert fresh["description"] == "sim2real clobbered", fresh
    assert fresh["timeoutInMinutes"] == 45, fresh


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
