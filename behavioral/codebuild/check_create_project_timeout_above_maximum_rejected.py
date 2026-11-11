"""create-project-timeout-above-maximum-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


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


def _through_role_propagation(fn, ctx):
    """Call fn(); retry a ClientError that means the service role's trust policy has not
    yet reached CodeBuild, up to a deadline. Any other ClientError, or success, is final."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return fn()
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
    proj = _through_role_propagation(
        lambda: cb.create_project(**_project_args(name, role, **over))["project"], ctx
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _all_project_names(cb, **kwargs):
    """Every project name, in server order, across pages. Order-preserving: the caller
    asserts a SEQUENCE, so pages are concatenated, never merged into a set."""
    names = []
    token = None
    for _ in range(50):  # bounded: never an unbounded pagination loop
        call = dict(kwargs)
        if token:
            call["nextToken"] = token
        resp = cb.list_projects(**call)
        names.extend(resp.get("projects", []))
        token = resp.get("nextToken")
        if not token:
            break
    return names


# ===== check =====

CHECK = "create-project-timeout-above-maximum-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProject MUST reject timeoutInMinutes above the modelled maximum (2160) and MUST
    accept exactly 2160, echoing it back unchanged."""
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    bad_name = ctx.unique_name("sim2real-behav-proj-")

    def _create_bad():
        return _through_role_propagation(
            lambda: cb.create_project(**_project_args(bad_name, role, timeoutInMinutes=2161)), ctx
        )

    try:
        code, message = _error(_create_bad)
    except AssertionError:
        # The target accepted the call: remove what it created before failing.
        ctx.on_cleanup(lambda: cb.delete_project(name=bad_name))
        raise
    assert (code, message) == (
        "InvalidInputException",
        "Invalid timeout. Should be between 5 minutes and 36 hours",
    ), (code, message)

    # Effect absent.
    got = cb.batch_get_projects(names=[bad_name])
    assert got.get("projects", []) == [], got
    assert bad_name in got.get("projectsNotFound", []), got
    assert bad_name not in _all_project_names(cb), bad_name

    # Control: the boundary value itself is accepted and stored verbatim.
    ok_name = ctx.unique_name("sim2real-behav-proj-")
    proj = _create_project(cb, ctx, ok_name, role, timeoutInMinutes=2160)
    assert proj["timeoutInMinutes"] == 2160, (
        f"the maximum timeout must be accepted and echoed exactly, got "
        f"{proj.get('timeoutInMinutes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
