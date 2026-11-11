"""build-failing-command-reaches-failed-terminal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


_SCENARIO = "codebuild-build-failing-command"


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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
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


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=5.0):
    """Poll BatchGetBuilds until the build reports buildComplete, bounded by a deadline.
    Returns the final Build dict, or None if the deadline passed while still running.
    Never sleeps as the assertion: the caller asserts on the returned terminal object."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion (or a harness kill) still gets stopped instead of billing for its
    whole timeoutInMinutes. The holder is mutated in place once the id is known."""
    holder = {"id": None}

    def _stop():
        bid = holder["id"]
        if not bid:
            return
        try:
            cb.stop_build(id=bid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_stop)
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


# ===== check =====

CHECK = "build-failing-command-reaches-failed-terminal"
GROUP = 'lifecycle'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A non-zero exit status from a buildspec command drives the build to the FAILED
    terminal with a FAILED BUILD phase carrying a diagnostic context - and the identical
    project still reaches SUCCEEDED for a zero-exit buildspec (positive control)."""
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")
    _create_project(cb, ctx, name, role, timeoutInMinutes=5)

    def _spec(cmd):
        return (
            "version: 0.2\n"
            "phases:\n"
            "  build:\n"
            "    commands:\n"
            f"      - {cmd}\n"
        )

    # --- negative: a command that exits 7 must FAIL the build -------------------
    bad = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=_spec("exit 7"))
    bad_final = _poll_build_terminal(cb, bad["id"], timeout_s=600)
    assert bad_final is not None, f"build {bad['id']} never reported buildComplete"
    assert bad_final["buildStatus"] == "FAILED", (
        f"a buildspec command exiting 7 must yield buildStatus FAILED, got "
        f"{bad_final['buildStatus']!r}"
    )
    bad_phases = {p.get("phaseType"): p for p in bad_final.get("phases", [])}
    build_phase = bad_phases.get("BUILD")
    assert build_phase is not None, f"no BUILD phase reported: {bad_final.get('phases')}"
    assert build_phase.get("phaseStatus") == "FAILED", (
        f"BUILD phase must be FAILED, got {build_phase.get('phaseStatus')!r}"
    )
    assert build_phase.get("contexts"), (
        f"a failed BUILD phase must carry a diagnostic context, got {build_phase!r}"
    )
    assert bad_final.get("buildComplete") is True, bad_final.get("buildComplete")

    # --- control: the same project, a zero-exit buildspec, must SUCCEED ---------
    good = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=_spec("echo sim2real-control-ok"))
    good_final = _poll_build_terminal(cb, good["id"], timeout_s=600)
    assert good_final is not None, f"control build {good['id']} never reported buildComplete"
    assert good_final["buildStatus"] == "SUCCEEDED", (
        f"control build must SUCCEED on the same project, got "
        f"{good_final['buildStatus']!r}; phases={good_final.get('phases')}"
    )
    good_phases = {p.get("phaseType"): p for p in good_final.get("phases", [])}
    assert good_phases.get("BUILD", {}).get("phaseStatus") == "SUCCEEDED", good_phases.get("BUILD")
    assert good_final["id"] != bad_final["id"], "two StartBuild calls must mint distinct build ids"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
