"""stop-build-during-pre-build-stops-exactly-that-phase-and-leaves-the-rest-unrun."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# What the check relies on:
#   - StopBuild issued while `currentPhase == "PRE_BUILD"` leaves EXACTLY ONE phase carrying
#     `phaseStatus == "STOPPED"`, and it is PRE_BUILD. BuildPhase lists STOPPED as a valid
#     phaseStatus ("The build phase stopped",
#     https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BuildPhase.html); the stop is
#     attributable to one specific in-flight phase, which a target stamping every phase STOPPED
#     does not satisfy.
#   - The phases BEFORE the stopped one keep their SUCCEEDED status (INSTALL here).
#   - The phases AFTER the stopped one never reach SUCCEEDED. Asserted as a set difference
#     against the twin control, so it holds whether they are omitted or reported unfinished.
#   - The stopped PRE_BUILD phase reports less elapsed time than the twin's completed PRE_BUILD.
#   - A STOPPED build reports an `endTime`.
#   - `currentPhase` reaches the literal string "PRE_BUILD" while a pre_build command is
#     running, so it can be polled for.
# NOT ASSERTED HERE, deliberately: whether a second StopBuild on an already-STOPPED build is a
#   no-op or a rejection.
# WALL CLOCK: both builds are issued before either is polled. The subject is stopped as soon as
#   it enters PRE_BUILD, so the cost is roughly the control's latency: 420s terminal deadline
#   plus a 360s bounded wait to reach PRE_BUILD plus up to 180s of IAM trust propagation.

# ===== helpers =====

_SCENARIO = "codebuild-stop-mid-phase"
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


def _get_builds(cb, ids):
    got = cb.batch_get_builds(ids=list(ids))
    by_id = {b["id"]: b for b in got.get("builds", [])}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got {sorted(by_id)!r} "
        f"and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


def _poll_until_phase(cb, build_id, phase, *, timeout_s, interval_s=5.0):
    """Wait for `build_id` to report currentPhase == `phase`, bounded. RAISES on timeout, and
    RAISES if the build reaches a terminal state first - a build that finished before it could
    be stopped invalidates the check rather than passing it."""
    deadline = time.monotonic() + timeout_s
    while True:
        build = _get_builds(cb, [build_id])[build_id]
        if build.get("currentPhase") == phase:
            return build
        assert build.get("buildComplete") is not True, (
            f"build {build_id!r} completed with buildStatus {build.get('buildStatus')!r} before "
            f"it ever reported currentPhase {phase!r}; phases={_phases(build)!r}"
        )
        assert time.monotonic() < deadline, (
            f"build {build_id!r} never reported currentPhase {phase!r} within {timeout_s}s; "
            f"last currentPhase={build.get('currentPhase')!r} phases={_phases(build)!r}"
        )
        time.sleep(interval_s)


def _poll_builds_terminal(cb, ids, *, timeout_s, interval_s=5.0):
    """Poll one BatchGetBuilds over every id until all report buildComplete, bounded by a
    deadline. RAISES on timeout - a truncated poll would assert on a stale build."""
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


def _succeeded_types(build):
    return {p.get("phaseType") for p in build.get("phases", [])
            if p.get("phaseStatus") == "SUCCEEDED"}


def _stopped_types(build):
    return [p.get("phaseType") for p in build.get("phases", [])
            if p.get("phaseStatus") == "STOPPED"]


# ===== check =====

CHECK = "stop-build-during-pre-build-stops-exactly-that-phase-and-leaves-the-rest-unrun"
GROUP = 'state-machine'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild issued while the build is provably inside PRE_BUILD marks EXACTLY that phase STOPPED,
    keeps INSTALL SUCCEEDED and never runs BUILD or POST_BUILD, while a same-instant twin differing only
    in its pre_build sleep runs all four phases to SUCCEEDED with no STOPPED status."""
    cb = ctx.client("codebuild")

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
    ])

    def _spec(pre_build_sleep: str) -> str:
        return (
            "version: 0.2\n"
            "phases:\n"
            "  install:\n"
            "    commands:\n"
            "      - echo sim2real-install\n"
            "  pre_build:\n"
            "    commands:\n"
            f"      - sleep {pre_build_sleep}\n"
            "  build:\n"
            "    commands:\n"
            "      - echo sim2real-build\n"
            "  post_build:\n"
            "    commands:\n"
            "      - echo sim2real-post-build\n"
        )

    # 300s gives a wide window to catch the subject inside PRE_BUILD. short_sleep must clear the
    # subject's worst-case interruption latency (bounded by _poll_until_phase's 5s poll interval
    # plus StopBuild's own processing lag - MEASURED at up to a few seconds) with a wide margin, so
    # the twin's fully-run PRE_BUILD duration is unambiguously larger than the subject's cut-short
    # one on every run.
    long_sleep = 300
    short_sleep = 60
    spec_subject = _spec(str(long_sleep))
    spec_control = _spec(str(short_sleep))

    name = ctx.unique_name("sim2real-behav-proj-stopphase-")
    _create_project(cb, ctx, name, role, spec_subject)

    subject = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_subject)
    control = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_control)
    assert subject["id"] != control["id"], (
        f"two StartBuild calls must mint distinct ids, both were {subject['id']!r}"
    )

    # Bounded wait for the live transition this check exists to interrupt.
    _poll_until_phase(cb, subject["id"], "PRE_BUILD", timeout_s=360)
    cb.stop_build(id=subject["id"])

    final = _poll_builds_terminal(cb, [subject["id"], control["id"]], timeout_s=420)
    stopped = final[subject["id"]]
    ok = final[control["id"]]

    # --- positive control: the same project runs all four phases to SUCCEEDED -------
    assert ok["buildStatus"] == "SUCCEEDED", (
        f"the twin control is what separates 'StopBuild stopped it' from 'nothing on this "
        f"project ever succeeds'. Got {ok['buildStatus']!r}; phases={_phases(ok)!r}; "
        f"contexts={[p.get('contexts') for p in ok.get('phases', [])]!r}"
    )
    control_ok = _succeeded_types(ok)
    assert {"INSTALL", "PRE_BUILD", "BUILD", "POST_BUILD"} <= control_ok, (
        f"the control must run all four buildspec phases to SUCCEEDED; its SUCCEEDED set is "
        f"{sorted(control_ok)!r}; phases={_phases(ok)!r}"
    )
    assert _stopped_types(ok) == [], (
        f"nothing stopped the control, so no phase of it may report STOPPED; it reports "
        f"{_stopped_types(ok)!r} stopped; phases={_phases(ok)!r}"
    )

    # --- the subject: exactly PRE_BUILD absorbed the stop ---------------------------
    assert stopped["buildStatus"] == "STOPPED", (
        f"a build stopped mid-PRE_BUILD must reach buildStatus STOPPED, got "
        f"{stopped['buildStatus']!r}; phases={_phases(stopped)!r}"
    )
    assert stopped.get("endTime") is not None, (
        f"a STOPPED build must report an endTime, got {stopped.get('endTime')!r}"
    )
    assert _stopped_types(stopped) == ["PRE_BUILD"], (
        f"exactly one phase - the one that was running - must carry phaseStatus STOPPED, and it "
        f"must be PRE_BUILD; the build reports {_stopped_types(stopped)!r} stopped; "
        f"phases={_phases(stopped)!r}"
    )
    by_type = {p.get("phaseType"): p for p in stopped.get("phases", [])}
    install = by_type.get("INSTALL")
    assert install is not None and install.get("phaseStatus") == "SUCCEEDED", (
        f"INSTALL completed before the stop, so it must remain SUCCEEDED; got {install!r}; "
        f"phases={_phases(stopped)!r}"
    )
    stopped_ok = _succeeded_types(stopped)
    assert stopped_ok & {"BUILD", "POST_BUILD"} == set(), (
        f"a build stopped during PRE_BUILD must never run BUILD or POST_BUILD to SUCCEEDED; its "
        f"SUCCEEDED set is {sorted(stopped_ok)!r}; phases={_phases(stopped)!r}"
    )
    assert stopped_ok < control_ok, (
        f"the stopped build's SUCCEEDED phases must be a STRICT subset of the twin control's: "
        f"subject={sorted(stopped_ok)!r} vs control={sorted(control_ok)!r}"
    )

    # --- two-sided clock: the phase really ran, and was really cut short ------------
    # A fixed ">= 5s" floor does not hold on real AWS: a NO_SOURCE / standard:7.0 /
    # BUILD_GENERAL1_SMALL build can provision fast enough that the whole lifecycle from
    # provisioning to a PRE_BUILD stop can land under 5s total, and CodeBuild reports
    # durationInSeconds as a floored integer - a phase interrupted within its first second reports
    # 0, not "at least a few seconds". A hardcoded lower bound is the wrong shape here; the real
    # discriminating fact is COMPARATIVE: the twin control's PRE_BUILD ran short_sleep to actual
    # completion, so the subject's interrupted PRE_BUILD must report STRICTLY LESS elapsed time
    # than that - proving it was cut short relative to a phase that was allowed to finish, without
    # pinning an absolute wall-clock floor. This needs a real margin: a 3s twin can TIE the subject
    # when it is caught late in a 5s poll interval, so short_sleep is chosen to clear that latency.
    pre = by_type.get("PRE_BUILD")
    assert pre is not None, f"no PRE_BUILD phase reported; phases={_phases(stopped)!r}"
    pre_dur = pre.get("durationInSeconds")
    assert pre_dur is not None, (
        f"the stopped PRE_BUILD phase must report a durationInSeconds; got {pre!r}"
    )
    control_pre = {p.get("phaseType"): p for p in ok.get("phases", [])}.get("PRE_BUILD")
    assert control_pre is not None, (
        f"the control's PRE_BUILD phase is missing; phases={_phases(ok)!r}"
    )
    control_pre_dur = control_pre.get("durationInSeconds")
    assert control_pre_dur is not None, (
        f"the control's PRE_BUILD phase must report a durationInSeconds; got {control_pre!r}"
    )
    assert pre_dur < control_pre_dur, (
        f"the subject's PRE_BUILD was interrupted mid-sleep while the twin control's PRE_BUILD "
        f"ran its sleep to completion, so the subject must report STRICTLY LESS elapsed time - "
        f"subject durationInSeconds={pre_dur!r}s vs control durationInSeconds={control_pre_dur!r}s"
    )
    assert pre_dur < long_sleep - 30, (
        f"StopBuild must have CUT SHORT the {long_sleep}s sleep, but PRE_BUILD reports "
        f"{pre_dur!r}s - the phase was allowed to run to completion"
    )

    # An independent read at a different operation than StartBuild/BatchGetBuilds/StopBuild.
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
    assert sorted(listed) == sorted([subject["id"], control["id"]]), (
        f"ListBuildsForProject must report exactly the two builds this check started for "
        f"{name!r}; it reported {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
