"""phase-durations-equal-their-own-windows-and-the-slow-phase-dominates."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# What the check relies on:
#   - For every phase that reports both `startTime` and `endTime`,
#     `durationInSeconds == round((endTime - startTime).total_seconds())`. BuildPhase documents
#     durationInSeconds as "How long, in seconds, between the starting and ending times of the
#     build's phase" (https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BuildPhase.html),
#     a DEFINITION, so this is a derivation rule; the rounding mode is not documented, so a
#     +/-1s tolerance is applied.
#   - Phase windows do not overlap: consecutive phases satisfy endTime[i] <= startTime[i+1].
#   - The last reported phase is COMPLETED, and it is the only phase with no
#     `durationInSeconds`.
#   - A `sleep N` in the buildspec's build phase (N minted here, 15..25) puts the BUILD phase's
#     durationInSeconds at >= N and < N + 90, and strictly above every other buildspec phase's
#     duration. The upper bound is a two-sided clock, not a performance claim.
#   - The sum of the per-phase durations does not exceed the Build's own
#     round(endTime - startTime) window (+2s of rounding slack).
#   - A terminal build's phase table is frozen under repeated reads.
# NOTE ON THE `sleep` IN THE BUILDSPEC: it runs inside the build container and is the SUBJECT
#   being measured, not a wait for a condition in this check's own body. Every wait in the body
#   is a bounded retry that raises on timeout.
# WALL CLOCK: ONE build of roughly (container provisioning + N seconds). Terminal deadline 360s
#   plus up to 180s of IAM trust propagation.

# ===== helpers =====
# _poll_build_terminal RAISES on timeout, so a truncated poll can never turn into an assertion
# on a stale object.

_SCENARIO = "codebuild-phase-clock"
_IMAGE = "aws/codebuild/standard:7.0"

# Phases whose commands this buildspec supplies, so their durations are comparable.
_BUILDSPEC_PHASES = ["INSTALL", "PRE_BUILD", "BUILD", "POST_BUILD"]


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
        "timeoutInMinutes": 10,
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


def _get_build(cb, build_id):
    got = cb.batch_get_builds(ids=[build_id])
    builds = got.get("builds", [])
    assert builds, (
        f"BatchGetBuilds lost build {build_id!r}: buildsNotFound="
        f"{got.get('buildsNotFound')!r}"
    )
    return builds[0]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=5.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. RAISES on timeout - a
    truncated poll would assert on a stale build."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = _get_build(cb, build_id)
        if last.get("buildComplete") is True:
            return last
        assert time.monotonic() < deadline, (
            f"build {build_id!r} never reported buildComplete within {timeout_s}s; last "
            f"buildStatus={last.get('buildStatus')!r} currentPhase="
            f"{last.get('currentPhase')!r}"
        )
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _fingerprint(build):
    return [(p.get("phaseType"), p.get("phaseStatus"), p.get("durationInSeconds"))
            for p in build.get("phases", [])]


def _window(phase):
    """(startTime, endTime) if the phase reports both, else None."""
    start, end = phase.get("startTime"), phase.get("endTime")
    if start is None or end is None:
        return None
    return start, end


# ===== check =====

CHECK = "phase-durations-equal-their-own-windows-and-the-slow-phase-dominates"
GROUP = 'lifecycle'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each BuildPhase's `durationInSeconds` equals its OWN startTime-to-endTime window, windows do
    not overlap and fit inside the Build's own window, and the phase given a `sleep N` (N minted this
    run) dominates every other buildspec phase's duration."""
    cb = ctx.client("codebuild")

    # Minted here, so no fixed value can match it.
    sleep_s = random.SystemRandom().randrange(15, 26)

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
    ])

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  install:\n"
        "    commands:\n"
        "      - echo sim2real-install\n"
        "  pre_build:\n"
        "    commands:\n"
        "      - echo sim2real-pre-build\n"
        "  build:\n"
        "    commands:\n"
        # The subject under measurement, not a wait in this check's own body.
        '      - sleep "$SIM2REAL_SLEEP"\n'
        "  post_build:\n"
        "    commands:\n"
        "      - echo sim2real-post-build\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-phaseclock-")
    _create_project(cb, ctx, name, role, buildspec)

    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_SLEEP", "value": str(sleep_s), "type": "PLAINTEXT"}])
    build = _poll_build_terminal(cb, started["id"], timeout_s=360)

    assert build["buildStatus"] == "SUCCEEDED", (
        f"the build must succeed for its phase clock to mean anything; got "
        f"{build['buildStatus']!r}; phases={_phases(build)!r}; "
        f"contexts={[p.get('contexts') for p in build.get('phases', [])]!r}"
    )
    phases = build.get("phases") or []
    assert len(phases) >= len(_BUILDSPEC_PHASES), (
        f"a SUCCEEDED four-phase build must report at least {len(_BUILDSPEC_PHASES)} phases, "
        f"reported {_phases(build)!r}"
    )

    # --- H1: each duration is its own window, not an independent number -------------
    measured = {}
    for phase in phases:
        ptype = phase.get("phaseType")
        window = _window(phase)
        if window is None:
            # A phase with no closed window must also report no duration - the two facts are
            # the same fact, and this is the shape that catches a fabricated duration.
            assert phase.get("durationInSeconds") is None, (
                f"phase {ptype!r} reports durationInSeconds "
                f"{phase.get('durationInSeconds')!r} with no closed startTime/endTime window: "
                f"startTime={phase.get('startTime')!r} endTime={phase.get('endTime')!r}"
            )
            continue
        start, end = window
        span = (end - start).total_seconds()
        assert span >= 0, (
            f"phase {ptype!r} ends before it starts: startTime={start!r} endTime={end!r}"
        )
        reported = phase.get("durationInSeconds")
        assert reported is not None, (
            f"phase {ptype!r} reports a closed window {start!r}..{end!r} but no "
            f"durationInSeconds"
        )
        assert abs(reported - round(span)) <= 1, (
            f"phase {ptype!r} reports durationInSeconds {reported!r} but its own window "
            f"{start!r}..{end!r} spans {span:.3f}s (rounds to {round(span)}); the two must "
            f"agree within 1s"
        )
        measured[ptype] = reported

    # --- H2: windows are ordered and do not overlap --------------------------------
    closed = [(p.get("phaseType"), *_window(p)) for p in phases if _window(p) is not None]
    for (a_type, _a_start, a_end), (b_type, b_start, _b_end) in zip(closed, closed[1:]):
        assert a_end <= b_start, (
            f"phase {a_type!r} ends at {a_end!r}, after phase {b_type!r} starts at "
            f"{b_start!r}; consecutive phase windows must not overlap"
        )

    # --- H3: COMPLETED terminates the table ---------------------------------------
    types = [p.get("phaseType") for p in phases]
    assert types[-1] == "COMPLETED", (
        f"the last phase of a terminal build must be COMPLETED, the table ends with "
        f"{types[-1]!r}; full list {types!r}"
    )

    # --- H4: the slow phase dominates, two-sided ----------------------------------
    for ptype in _BUILDSPEC_PHASES:
        assert ptype in measured, (
            f"the buildspec supplies commands for {ptype!r}, so it must appear with a closed "
            f"window and a duration; measured durations are {measured!r}"
        )
    build_dur = measured["BUILD"]
    assert build_dur >= sleep_s, (
        f"the build phase sleeps {sleep_s}s, so its durationInSeconds must be at least that; "
        f"reported {build_dur!r}. Measured durations: {measured!r}"
    )
    assert build_dur < sleep_s + 90, (
        f"the build phase's durationInSeconds {build_dur!r} is more than 90s above the {sleep_s}s "
        f"it was told to sleep - a duration detached from the work done. "
        f"Measured durations: {measured!r}"
    )
    others = {k: v for k, v in measured.items()
              if k in _BUILDSPEC_PHASES and k != "BUILD"}
    assert others, f"expected sibling buildspec phase durations, measured {measured!r}"
    assert build_dur > max(others.values()), (
        f"the only phase given real work must take strictly longer than the echo-only phases: "
        f"BUILD={build_dur!r} vs {others!r}"
    )

    # --- H5: the table fits inside the Build's own window -------------------------
    b_start, b_end = build.get("startTime"), build.get("endTime")
    assert b_start is not None and b_end is not None, (
        f"a terminal build must report both startTime and endTime, got {b_start!r}..{b_end!r}"
    )
    build_span = round((b_end - b_start).total_seconds())
    total = sum(measured.values())
    assert total <= build_span + 2, (
        f"the per-phase durations sum to {total}s, which exceeds the Build's own window of "
        f"{build_span}s ({b_start!r}..{b_end!r}); phases cannot outlast the build. "
        f"Measured durations: {measured!r}"
    )
    assert build_span >= sleep_s, (
        f"the Build's own window is {build_span}s, shorter than the {sleep_s}s its build phase "
        f"was told to sleep: {b_start!r}..{b_end!r}"
    )

    # --- H6: state must not advance on reads --------------------------------------
    baseline = _fingerprint(build)
    for i in range(3):
        again = _get_build(cb, build["id"])
        assert _fingerprint(again) == baseline, (
            f"read {i + 1} of a TERMINAL build changed its phase table: baseline {baseline!r} "
            f"became {_fingerprint(again)!r}"
        )

    # An independent read at a different operation than StartBuild/BatchGetBuilds.
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
    assert listed == [build["id"]], (
        f"ListBuildsForProject must report exactly the one build this check started for "
        f"{name!r}; it reported {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
