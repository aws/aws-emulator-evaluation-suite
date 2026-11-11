"""build-executes-buildspec-and-exports-computed-variable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


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
        Tags=[{"Key": "sim2real", "Value": role_name}],
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
    # No fixed wait for trust-policy propagation: _create_project's retry loop below
    # already treats the "role not yet assumable" ClientError as transient and retries
    # it, bounded by a deadline — that is the wait, so a second unconditional sleep here
    # would only pad every run's wall clock without covering any case the retry misses.
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
        "tags": [{"key": "sim2real", "value": name}],
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
    def _delete():
        try:
            cb.delete_project(name=proj["name"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    return proj


def _error(fn):
    """The ClientError response *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _all_project_names(cb):
    """Every project name ListProjects returns, across every page."""
    names, kwargs = [], {}
    while True:
        page = cb.list_projects(**kwargs)
        names.extend(page.get("projects") or [])
        token = page.get("nextToken")
        if not token:
            return names
        kwargs = {"nextToken": token}


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=5.0):
    """Poll BatchGetBuilds until the build reports buildComplete, bounded by a deadline.
    Returns the final Build dict and raises if the deadline passes while still running."""
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
            raise AssertionError(f"build {build_id} not complete within {timeout_s}s: {last!r}")
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

CHECK = "build-executes-buildspec-and-exports-computed-variable"
GROUP = 'lifecycle'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build actually EXECUTES the buildspec: it computes seed*7+3 in a shell command and
    exports the result, and BatchGetBuilds reports that exact value with buildStatus SUCCEEDED."""
    cb = ctx.client("codebuild")
    role = _create_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")

    # Seed derived from the unique name, so the expected answer is unique to this run.
    seed = 1000 + (abs(hash(name)) % 9000)
    expected = str(seed * 7 + 3)

    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_RESULT\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - export SIM2REAL_RESULT="$(( SIM2REAL_SEED * 7 + 3 ))"\n'
        '      - echo "sim2real computed $SIM2REAL_RESULT"\n'
    )

    _create_project(cb, ctx, name, role, source={"type": "NO_SOURCE", "buildspec": buildspec},
                    timeoutInMinutes=5)

    build = _start_build_with_stop_registered(
        cb, ctx,
        projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_SEED", "value": str(seed), "type": "PLAINTEXT"},
        ],
    )
    # The build's own timeoutInMinutes=5 ends it in a terminal status; this deadline only bounds
    # queueing on top of that, sized from the default class budget.
    final = _poll_build_terminal(cb, build["id"], timeout_s=3600)

    phases = {p.get("phaseType"): p for p in final.get("phases", [])}
    assert final["buildStatus"] == "SUCCEEDED", (
        f"buildStatus={final['buildStatus']!r}; phases="
        f"{[(p.get('phaseType'), p.get('phaseStatus'), p.get('contexts')) for p in final.get('phases', [])]}"
    )
    assert phases.get("BUILD", {}).get("phaseStatus") == "SUCCEEDED", (
        f"BUILD phase not SUCCEEDED: {phases.get('BUILD')}"
    )
    assert final.get("buildComplete") is True, final.get("buildComplete")

    exported = {v["name"]: v["value"] for v in final.get("exportedEnvironmentVariables", [])}
    assert exported.get("SIM2REAL_RESULT") == expected, (
        f"buildspec was not executed: exportedEnvironmentVariables={exported}, "
        f"expected SIM2REAL_RESULT={expected!r} for seed={seed}"
    )

    # The project is deleted and proven gone: in-band miss, absent from the listing, unusable.
    cb.delete_project(name=name)
    got = cb.batch_get_projects(names=[name])
    assert got.get("projectsNotFound") == [name] and not got.get("projects"), (
        f"BatchGetProjects on the deleted project must report it in projectsNotFound only, got "
        f"projectsNotFound={got.get('projectsNotFound')!r}, {len(got.get('projects') or [])} projects"
    )
    listed = _all_project_names(cb)
    assert name not in listed, f"the deleted project is still in ListProjects ({len(listed)} names)"
    dead = _error(lambda: cb.update_project(name=name, description="x"))
    code = dead["Error"]["Code"]
    status = dead["ResponseMetadata"]["HTTPStatusCode"]
    message = dead["Error"].get("Message") or ""
    assert code == "ResourceNotFoundException", (
        f"UpdateProject on the deleted project must raise ResourceNotFoundException, got {code!r}"
    )
    assert status == 400, f"UpdateProject on the deleted project must answer HTTP 400, got {status}"
    expected_message = "Project does not exist"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
