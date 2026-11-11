"""codebuild-invalid-buildspec-yaml-rejected-before-the-build-phase-runs."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-bad-buildspec"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role and its inline policies; an already-deleted role is fine."""
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
    """A CodeBuild-assumable service role carrying exactly `statements`."""
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
    # IAM propagation exposes no condition to poll; _create_project retries the trust error.
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown on success."""
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


_BUILD_TIMEOUT_S = 240.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_builds_terminal(cb, build_ids, *, timeout_s, interval_s=2.0):
    """Poll BatchGetBuilds until every build is complete; an id maps to None if still running."""
    deadline = time.monotonic() + timeout_s
    done = {}
    while True:
        pending = [b for b in build_ids if b not in done]
        got = cb.batch_get_builds(ids=pending)
        by_id = {b["id"]: b for b in got.get("builds", [])}
        lost = [b for b in pending if b not in by_id]
        assert not lost, f"BatchGetBuilds lost build(s) {lost!r}: {got!r}"
        for build_id in pending:
            if by_id[build_id].get("buildComplete") is True:
                done[build_id] = by_id[build_id]
        if len(done) == len(build_ids):
            return done
        if time.monotonic() >= deadline:
            return {b: done.get(b) for b in build_ids}
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]

CHECK = "codebuild-invalid-buildspec-yaml-rejected-before-the-build-phase-runs"
GROUP = 'buildspec-semantics'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A tab-indented (unparseable YAML) buildspec fails the build in DOWNLOAD_SOURCE only, with a
    parser diagnostic, no BUILD phase and no exports; a well-formed one exports seed*7+3.
    """
    cb = ctx.client("codebuild")

    good_spec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_RESULT\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - export SIM2REAL_RESULT="$(( SIM2REAL_SEED * 7 + 3 ))"\n'
    )
    name = ctx.unique_name("sim2real-behav-proj-spec-")
    _create_project(cb, ctx, name, _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"}]), good_spec)

    # Tabs are illegal as YAML indentation. CodeBuild accepts weaker malformations:
    # `commands: <scalar>` is coerced to one command and `commands: []` is an empty phase.
    bad_spec = (
        "version: 0.2\n"
        "phases:\n"
        "\tbuild:\n"
        "\t\tcommands:\n"
        "\t\t\t- echo tab-indented-and-unparseable\n"
    )
    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=bad_spec)
    # Positive control: the same project with a well-formed buildspec, run alongside.
    seed = 1000 + (abs(hash(name)) % 9000)
    good_started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_SEED", "value": str(seed), "type": "PLAINTEXT"}])
    finished = _poll_builds_terminal(
        cb, [started["id"], good_started["id"]], timeout_s=_budget_s(ctx, _BUILD_TIMEOUT_S))
    if None in finished.values() and _budget_spent(ctx):
        raise TimeoutError("both builds reporting buildComplete: the run budget ended first; not graded")
    bad, good = finished[started["id"]], finished[good_started["id"]]
    assert bad is not None, f"build {started['id']!r} never reported buildComplete"

    assert bad["buildStatus"] == "FAILED", (
        f"a malformed buildspec must fail the build, got {bad['buildStatus']!r}; "
        f"phases={_phases(bad)!r}"
    )
    failed_phases = [p for p in bad.get("phases", []) if p.get("phaseStatus") == "FAILED"]
    assert [p.get("phaseType") for p in failed_phases] == ["DOWNLOAD_SOURCE"], (
        f"the parse refusal must land in DOWNLOAD_SOURCE and nowhere else, phases were "
        f"{_phases(bad)!r}"
    )
    context = " ".join(
        (c.get("message") or "") for c in (failed_phases[0].get("contexts") or []))
    # AWS returns the parser's own message ('found character that cannot start any token at
    # line 2'), not wrapped in a YAML_FILE_ERROR classification.
    assert "cannot start any token" in context, (
        f"the DOWNLOAD_SOURCE context did not report a YAML parse failure: {context!r}"
    )

    phase_types = [p.get("phaseType") for p in bad.get("phases", [])]
    assert "BUILD" not in phase_types, (
        f"the BUILD phase must never be entered for an unparseable buildspec, phases were "
        f"{_phases(bad)!r}"
    )
    assert bad.get("exportedEnvironmentVariables") in (None, []), (
        f"a build that never reached its BUILD phase exported "
        f"{bad.get('exportedEnvironmentVariables')!r}"
    )

    assert good is not None, f"control build {good_started['id']!r} never completed"
    assert good["buildStatus"] == "SUCCEEDED", (
        f"the control build must SUCCEED on the same project, got "
        f"{good['buildStatus']!r}; phases={_phases(good)!r}"
    )
    exported = dict((v["name"], v["value"])
                    for v in good.get("exportedEnvironmentVariables", []))
    assert exported.get("SIM2REAL_RESULT") == str(seed * 7 + 3), (
        f"the control build exported {exported!r}, expected SIM2REAL_RESULT="
        f"{str(seed * 7 + 3)!r} for seed={seed}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
