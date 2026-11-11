"""timeout-in-minutes-kills-the-running-build-and-marks-that-phase-timed-out."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# An EXECUTION timeout (timeoutInMinutes) ends a running build with buildStatus FAILED; TIMED_OUT
# is stamped only on the phase that was running. A QUEUE timeout (queuedTimeoutInMinutes) reaches
# buildStatus TIMED_OUT because the build never leaves QUEUED.
# This check deliberately waits out the documented 5-minute minimum timeout; both builds run
# concurrently so the cost is one timeout (~10 billed BUILD_GENERAL1_SMALL build-minutes).

_SCENARIO = "codebuild-build-timeout"
_IMAGE = "aws/codebuild/standard:7.0"
_TIMEOUT_MINUTES = 5  # the documented minimum for timeoutInMinutes, not an account quota


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies, tolerating NoSuchEntity."""
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
        "timeoutInMinutes": _TIMEOUT_MINUTES,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    # Trust propagation exposes no condition to poll, so this bounded retry IS the wait.
    deadline = time.monotonic() + 180
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


def _get_builds(cb, ids):
    got = cb.batch_get_builds(ids=list(ids))
    by_id = {b["id"]: b for b in got.get("builds", [])}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got {sorted(by_id)!r} "
        f"and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


def _poll_builds_terminal(cb, ids, *, timeout_s, interval_s=10.0):
    """Poll one BatchGetBuilds over every id until all report buildComplete, bounded by a
    deadline. Raises on timeout rather than returning builds that are still running."""
    deadline = time.monotonic() + timeout_s
    while True:
        by_id = _get_builds(cb, ids)
        pending = [i for i, b in by_id.items() if b.get("buildComplete") is not True]
        if not pending:
            return by_id
        assert time.monotonic() < deadline, (
            f"after {timeout_s}s these builds never reported buildComplete: "
            f"{[(i, by_id[i].get('buildStatus'), by_id[i].get('currentPhase')) for i in pending]!r}"
        )
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _statuses(build):
    return [p.get("phaseStatus") for p in build.get("phases", [])]


def _context_text(phase):
    parts = []
    for c in (phase.get("contexts") or []):
        parts.append(c.get("statusCode") or "")
        parts.append(c.get("message") or "")
    return " ".join(parts)


# ===== check =====

CHECK = "timeout-in-minutes-kills-the-running-build-and-marks-that-phase-timed-out"
GROUP = 'visibility-timeout-ttl'
SERVICES = ['codebuild']


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Project.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A build overrunning a 5-minute timeoutInMinutes ends FAILED with only BUILD marked TIMED_OUT.

    A twin build that finishes in time on the same project succeeds with no TIMED_OUT phase.
    """
    cb = ctx.client("codebuild")

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
    ])

    def _spec(seconds: str) -> str:
        return (
            "version: 0.2\n"
            "phases:\n"
            "  install:\n"
            "    commands:\n"
            "      - echo sim2real-install\n"
            "  build:\n"
            "    commands:\n"
            f"      - sleep {seconds}\n"
            "      - echo sim2real-build-finished\n"
        )

    # 3600s is far past the 5-minute timeout; 5s is far inside it. Nothing else differs.
    spec_overrun = _spec("3600")
    spec_control = _spec("5")

    name = ctx.unique_name("sim2real-behav-proj-timeout-")
    project = _create_project(cb, ctx, name, role, spec_overrun)
    assert project.get("timeoutInMinutes") == _TIMEOUT_MINUTES, (
        f"the project must store the requested timeout of {_TIMEOUT_MINUTES} minutes, it "
        f"reports {project.get('timeoutInMinutes')!r}"
    )

    overrun = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_overrun)
    control = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_control)
    assert overrun["id"] != control["id"], (
        f"two StartBuild calls must mint distinct ids, both were {overrun['id']!r}"
    )

    final = _poll_builds_terminal(cb, [overrun["id"], control["id"]], timeout_s=660)
    timed_out = final[overrun["id"]]
    ok = final[control["id"]]

    assert ok["buildStatus"] == "SUCCEEDED", (
        f"the control build is what separates 'the timeout fired' from 'every build on this "
        f"project fails'. Got {ok['buildStatus']!r}; phases={_phases(ok)!r}; "
        f"contexts={[p.get('contexts') for p in ok.get('phases', [])]!r}"
    )
    assert "TIMED_OUT" not in _statuses(ok), (
        f"the control finished well inside the {_TIMEOUT_MINUTES}-minute timeout, so no phase "
        f"may report TIMED_OUT; its phases are {_phases(ok)!r}"
    )

    # An execution timeout stamps TIMED_OUT on the running phase, not on the scalar buildStatus.
    assert timed_out["buildStatus"] == "FAILED", (
        f"a build sleeping 3600s under a {_TIMEOUT_MINUTES}-minute EXECUTION timeout must reach "
        f"buildStatus FAILED (the TIMED_OUT status lives on the phase, not the scalar), got "
        f"{timed_out['buildStatus']!r}; phases={_phases(timed_out)!r}; "
        f"contexts={[p.get('contexts') for p in timed_out.get('phases', [])]!r}"
    )
    assert timed_out.get("timeoutInMinutes") == _TIMEOUT_MINUTES, (
        f"the timed-out build must report the timeout it was run under "
        f"({_TIMEOUT_MINUTES}), it reports {timed_out.get('timeoutInMinutes')!r}"
    )
    by_type = {p.get("phaseType"): p for p in timed_out.get("phases", [])}
    build_phase = by_type.get("BUILD")
    assert build_phase is not None, (
        f"the timed-out build must report a BUILD phase - that is where the sleep ran; "
        f"phases={_phases(timed_out)!r}"
    )
    assert build_phase.get("phaseStatus") == "TIMED_OUT", (
        f"the BUILD phase held the overrunning command, so it must carry phaseStatus "
        f"TIMED_OUT; got {build_phase.get('phaseStatus')!r}; phases={_phases(timed_out)!r}"
    )
    timed_out_phase_types = [pt for pt, st in _phases(timed_out) if st == "TIMED_OUT"]
    assert timed_out_phase_types == ["BUILD"], (
        f"exactly the BUILD phase should carry TIMED_OUT - the kill must be localised to the "
        f"phase that was running, not smeared across the table; phases with TIMED_OUT were "
        f"{timed_out_phase_types!r}; full table={_phases(timed_out)!r}"
    )
    text = _context_text(build_phase).lower()
    assert "timed out" in text or "timeout" in text, (
        f"the TIMED_OUT BUILD phase must carry a context naming the timeout; its context text "
        f"was {_context_text(build_phase)[:400]!r}"
    )
    assert "sim2real-build-finished" not in _context_text(build_phase), (
        f"the command after the sleep must never have run; context text was "
        f"{_context_text(build_phase)[:400]!r}"
    )
    assert "INSTALL" in by_type and by_type["INSTALL"].get("phaseStatus") == "SUCCEEDED", (
        f"the phase before the overrun must still be SUCCEEDED, proving the kill is localised; "
        f"got {by_type.get('INSTALL')!r}; phases={_phases(timed_out)!r}"
    )

    # Two-sided bound: the timeout was enforced, and the time actually passed.
    start, end = timed_out.get("startTime"), timed_out.get("endTime")
    assert start is not None and end is not None, (
        f"a terminal build must report both startTime and endTime, got {start!r}..{end!r}"
    )
    span = (end - start).total_seconds()
    limit = _TIMEOUT_MINUTES * 60
    assert span >= limit - 60, (
        f"a build stamped TIMED_OUT under a {_TIMEOUT_MINUTES}-minute timeout must actually have "
        f"run for close to {limit}s; its own window {start!r}..{end!r} spans only {span:.1f}s - "
        f"the status was stamped without the time passing"
    )
    assert span < limit + limit, (
        f"the {_TIMEOUT_MINUTES}-minute timeout must have been ENFORCED: the build ran "
        f"{span:.1f}s, more than double its {limit}s limit"
    )

    listed = []
    token = None
    while True:
        kwargs = {"projectName": name}
        if token:
            kwargs["nextToken"] = token
        page = cb.list_builds_for_project(**kwargs)
        listed.extend(page.get("ids", []))
        token = page.get("nextToken")
        if not token:
            break
    assert sorted(listed) == sorted([overrun["id"], control["id"]]), (
        f"ListBuildsForProject must report exactly the two builds this check started for "
        f"{name!r}; it reported {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
