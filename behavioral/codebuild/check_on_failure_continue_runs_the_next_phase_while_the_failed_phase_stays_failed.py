"""on-failure-continue-runs-the-next-phase-while-the-failed-phase-stays-failed."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# What the check relies on:
#   - `phases/pre_build/on-failure: CONTINUE` makes the PRE_BUILD phase
#     `phaseStatus == "FAILED"` AND still runs the BUILD and POST_BUILD phases to SUCCEEDED
#     (https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html:
#     "on-failure ... CONTINUE - Continue to the next phase"). The ABORT-vs-CONTINUE
#     BUILD-ran difference is the discriminator, not the status word.
#   - The default (`on-failure` absent) is ABORT, so the ABORT arm leaves BUILD and
#     POST_BUILD out of the SUCCEEDED set.
#   - The overall build is FAILED in BOTH arms: CONTINUE changes phase flow, not the verdict.
#   - Both arms' failed PRE_BUILD phases carry a `contexts` entry naming the decimal exit
#     code the container computed from two random addends minted here.
#   - `on-failure` is accepted on a buildspec supplied through `buildspecOverride` on a
#     NO_SOURCE project.
# WALL CLOCK: both builds are issued before either is polled, so this costs ONE build's
#   latency. Shared terminal deadline 420s plus up to 180s of IAM trust propagation.

# ===== helpers =====
# _poll_builds_terminal polls both arms through ONE BatchGetBuilds so they are observed in the
# same instant, and RAISES rather than returning its last value on timeout.

_SCENARIO = "codebuild-on-failure"
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
        "timeoutInMinutes": 5,
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
    """BatchGetBuilds for several ids at once, as {id: Build}. A dropped build fails loudly."""
    got = cb.batch_get_builds(ids=list(ids))
    by_id = {b["id"]: b for b in got.get("builds", [])}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got {sorted(by_id)!r} "
        f"and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


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


def _by_type(build):
    return {p.get("phaseType"): p for p in build.get("phases", [])}


def _context_text(phase):
    parts = []
    for c in (phase.get("contexts") or []):
        parts.append(c.get("statusCode") or "")
        parts.append(c.get("message") or "")
    return " ".join(parts)


# ===== check =====

CHECK = "on-failure-continue-runs-the-next-phase-while-the-failed-phase-stays-failed"
GROUP = 'buildspec-semantics'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent builds differing only in `phases/pre_build/on-failure: CONTINUE` diverge after
    pre_build exits non-zero: the CONTINUE arm reports PRE_BUILD FAILED with BUILD and POST_BUILD
    SUCCEEDED, the default arm reports neither as SUCCEEDED."""
    cb = ctx.client("codebuild")

    exit_code = random.SystemRandom().randrange(3, 121)
    addend_a = exit_code // 2
    addend_b = exit_code - addend_a
    assert addend_a >= 1 and addend_a + addend_b == exit_code, (
        f"the addends must reconstruct the exit code: {addend_a}+{addend_b} != {exit_code}"
    )

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
    ])

    def _spec(on_failure_line: str) -> str:
        return (
            "version: 0.2\n"
            "phases:\n"
            "  install:\n"
            "    commands:\n"
            "      - echo sim2real-install\n"
            "  pre_build:\n"
            f"{on_failure_line}"
            "    commands:\n"
            "      - echo sim2real-pre-build\n"
            "      - exit $(( SIM2REAL_EXIT_A + SIM2REAL_EXIT_B ))\n"
            "  build:\n"
            "    commands:\n"
            "      - echo sim2real-build\n"
            "  post_build:\n"
            "    commands:\n"
            "      - echo sim2real-post-build\n"
        )

    # The ONLY difference between the two arms.
    spec_abort = _spec("")
    spec_continue = _spec("    on-failure: CONTINUE\n")

    name = ctx.unique_name("sim2real-behav-proj-onfailure-")
    _create_project(cb, ctx, name, role, spec_abort)

    env = [
        {"name": "SIM2REAL_EXIT_A", "value": str(addend_a), "type": "PLAINTEXT"},
        {"name": "SIM2REAL_EXIT_B", "value": str(addend_b), "type": "PLAINTEXT"},
    ]

    abort_started = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_abort,
        environmentVariablesOverride=env)
    cont_started = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_continue,
        environmentVariablesOverride=env)
    assert abort_started["id"] != cont_started["id"], (
        f"two StartBuild calls must mint distinct ids, both were {abort_started['id']!r}"
    )

    final = _poll_builds_terminal(
        cb, [abort_started["id"], cont_started["id"]], timeout_s=420)
    aborted = final[abort_started["id"]]
    continued = final[cont_started["id"]]

    # --- both arms really failed the same command, in the same phase -----------------
    for label, build in (("default/ABORT", aborted), ("CONTINUE", continued)):
        pre = _by_type(build).get("PRE_BUILD")
        assert pre is not None, (
            f"the {label} arm reported no PRE_BUILD phase; phases={_phases(build)!r}"
        )
        assert pre.get("phaseStatus") == "FAILED", (
            f"the {label} arm's pre_build command exits {exit_code}, so PRE_BUILD must be "
            f"FAILED; got {pre.get('phaseStatus')!r}; phases={_phases(build)!r}"
        )
        text = _context_text(pre)
        assert str(exit_code) in text, (
            f"the {label} arm's FAILED PRE_BUILD context must report the exit status the "
            f"container computed ({exit_code}, from {addend_a}+{addend_b}, a value that appears "
            f"nowhere in the buildspec); context text was {text[:400]!r}"
        )
        assert build["buildStatus"] == "FAILED", (
            f"the {label} arm must report buildStatus FAILED - on-failure changes phase flow, "
            f"not the verdict; got {build['buildStatus']!r}; phases={_phases(build)!r}"
        )

    # --- the one directive decides whether the later phases ran ---------------------
    abort_ok = _succeeded_types(aborted)
    cont_ok = _succeeded_types(continued)

    assert abort_ok & {"BUILD", "POST_BUILD"} == set(), (
        f"with `on-failure` absent (default ABORT) a FAILED pre_build must leave BUILD and "
        f"POST_BUILD out of the SUCCEEDED set; that arm reports {sorted(abort_ok)!r} as "
        f"SUCCEEDED; phases={_phases(aborted)!r}"
    )
    assert {"BUILD", "POST_BUILD"} <= cont_ok, (
        f"with `on-failure: CONTINUE` on pre_build, BUILD and POST_BUILD must still run to "
        f"SUCCEEDED; that arm's SUCCEEDED set is {sorted(cont_ok)!r}; "
        f"phases={_phases(continued)!r}"
    )
    assert abort_ok != cont_ok, (
        f"the two arms differ only in the `on-failure` directive, so their SUCCEEDED phase "
        f"sets must differ; both were {sorted(cont_ok)!r} - the directive was ignored"
    )
    # INSTALL succeeded in both, so the difference is not a global difference in wiring.
    assert "INSTALL" in abort_ok and "INSTALL" in cont_ok, (
        f"INSTALL must be SUCCEEDED in both arms, proving the two builds differ only after "
        f"pre_build; abort={sorted(abort_ok)!r} continue={sorted(cont_ok)!r}"
    )

    # An independent read at a different operation than StartBuild and BatchGetBuilds.
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
    assert sorted(listed) == sorted([abort_started["id"], cont_started["id"]]), (
        f"ListBuildsForProject must report exactly the two builds this check started for "
        f"{name!r}; it reported {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
