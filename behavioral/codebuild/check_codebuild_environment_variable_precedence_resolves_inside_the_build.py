"""codebuild-environment-variable-precedence-resolves-inside-the-build."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-env-precedence"
_IMAGE = "aws/codebuild/standard:7.0"


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


def _create_service_role(ctx, statements):
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`."""
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
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retry inside
    # _create_project (deadline + interval, on the specific transient error) is what
    # makes this correct — no unconditional wait here.
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"},
                       "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    deadline = time.monotonic() + 120
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion still gets stopped instead of billing its whole timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. Returns the terminal
    Build dict, or None if the deadline passed while it was still running."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got!r}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]

# ===== check =====

CHECK = "codebuild-environment-variable-precedence-resolves-inside-the-build"
GROUP = 'environment'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Inside the build, a StartBuild environmentVariablesOverride beats the project's
    environmentVariables, which beat the buildspec's env block, and a name defined once keeps its value;
    the per-build override leaves the project's stored definition unchanged."""
    cb = ctx.client("codebuild")

    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  variables:\n"
        '    SIM2REAL_B: "buildspec"\n'
        '    SIM2REAL_C: "buildspec"\n'
        '    SIM2REAL_D: "buildspec"\n'
        "  exported-variables:\n"
        "    - SIM2REAL_A\n"
        "    - SIM2REAL_B\n"
        "    - SIM2REAL_C\n"
        "    - SIM2REAL_D\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - echo "resolved A=$SIM2REAL_A B=$SIM2REAL_B C=$SIM2REAL_C D=$SIM2REAL_D"\n'
    )
    project_env = [
        {"name": "SIM2REAL_A", "value": "project", "type": "PLAINTEXT"},
        {"name": "SIM2REAL_B", "value": "project", "type": "PLAINTEXT"},
        {"name": "SIM2REAL_C", "value": "project", "type": "PLAINTEXT"},
    ]
    name = ctx.unique_name("sim2real-behav-proj-env-")
    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"}])
    _create_project(cb, ctx, name, role, buildspec,
                    environment={"type": "LINUX_CONTAINER", "image": _IMAGE,
                                 "computeType": "BUILD_GENERAL1_SMALL",
                                 "environmentVariables": project_env})

    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_C", "value": "override", "type": "PLAINTEXT"},
            {"name": "SIM2REAL_D", "value": "override", "type": "PLAINTEXT"},
        ])
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"
    assert build["buildStatus"] == "SUCCEEDED", (
        f"build was {build['buildStatus']!r}; phases={_phases(build)!r}"
    )

    exported = dict((v["name"], v["value"])
                    for v in build.get("exportedEnvironmentVariables", []))
    assert exported.get("SIM2REAL_A") == "project", (
        f"a name defined only on the project must keep the project's value, the shell saw "
        f"{exported.get('SIM2REAL_A')!r}; exported={exported!r}"
    )
    # Measured, and the opposite of the usual reading of the CodeBuild docs: the value
    # stored on the PROJECT wins over the buildspec's own env/variables entry for the
    # same name. An emulator that implements the documented order fails right here.
    assert exported.get("SIM2REAL_B") == "project", (
        f"the project's stored environmentVariables must beat the buildspec env block, the "
        f"shell saw {exported.get('SIM2REAL_B')!r}; exported={exported!r}"
    )
    assert exported.get("SIM2REAL_C") == "override", (
        f"a StartBuild override must beat both the buildspec and the project, the shell saw "
        f"{exported.get('SIM2REAL_C')!r}; exported={exported!r}"
    )
    assert exported.get("SIM2REAL_D") == "override", (
        f"a StartBuild override must beat the buildspec env block, the shell saw "
        f"{exported.get('SIM2REAL_D')!r}; exported={exported!r}"
    )

    stored = cb.batch_get_projects(names=[name])["projects"][0]
    stored_env = sorted((v["name"], v["value"], v["type"])
                        for v in stored["environment"].get("environmentVariables", []))
    assert stored_env == sorted((v["name"], v["value"], v["type"]) for v in project_env), (
        f"a per-build override must not mutate the project's stored environment, project now "
        f"holds {stored_env!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
