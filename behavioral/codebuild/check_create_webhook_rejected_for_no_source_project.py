"""create-webhook-rejected-for-no-source-project."""
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
    # Trust-relationship propagation is bounded by _create_project's own retry
    # deadline (below), not by an unconditional sleep here.
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


def _retry_transient_role(fn, ctx):
    """Call fn(), retrying while CodeBuild reports it cannot yet assume the freshly-created
    service role (IAM trust-policy propagation is asynchronous on real AWS)."""
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


def _create_project(cb, ctx, name, role, **over):
    """CreateProject, retrying through IAM trust-policy propagation; registers teardown
    immediately on success. Returns the project dict."""
    proj = _retry_transient_role(
        lambda: cb.create_project(**_project_args(name, role, **over))["project"], ctx
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj



CHECK = "create-webhook-rejected-for-no-source-project"
GROUP = 'overly-permissive'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebhook MUST be refused for a project whose source type cannot receive one
    (NO_SOURCE), leave no `webhook` member on the project, and leave the project fully usable;
    the source-type rule is not in the model, where CreateWebhookInput only requires projectName.
    """
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")
    proj = _create_project(cb, ctx, name, role)
    assert "webhook" not in proj, proj.get("webhook")

    def _create_webhook():
        return cb.create_webhook(projectName=name)

    try:
        code, message = _error(_create_webhook)
    except AssertionError:
        # The target accepted the call: remove what it created before failing.
        ctx.on_cleanup(lambda: cb.delete_webhook(projectName=name))
        raise
    assert (code, message) == (
        "InvalidInputException",
        "Invalid build type provided for NO_SOURCE type webhook",
    ), (code, message)

    # Effect absent: no webhook materialised on the project.
    got = cb.batch_get_projects(names=[name])
    assert len(got.get("projects", [])) == 1, got
    live = got["projects"][0]
    assert "webhook" not in live, (
        f"a rejected CreateWebhook left a webhook member behind: {live.get('webhook')!r}"
    )

    # Control: the project is undamaged and still mutable after the refusal. UpdateProject
    # re-validates the service role's trust policy just like CreateProject, so it is subject
    # to the same propagation delay and needs the same bounded retry.
    updated = _retry_transient_role(
        lambda: cb.update_project(name=name, description="sim2real post-refusal")["project"],
        ctx,
    )
    assert updated["description"] == "sim2real post-refusal", updated
    assert "webhook" not in updated, updated.get("webhook")

    # Terminal read: independent of the mutating UpdateProject call above.
    reread = cb.batch_get_projects(names=[name])["projects"][0]
    assert reread["description"] == "sim2real post-refusal", reread
    assert "webhook" not in reread, reread.get("webhook")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
