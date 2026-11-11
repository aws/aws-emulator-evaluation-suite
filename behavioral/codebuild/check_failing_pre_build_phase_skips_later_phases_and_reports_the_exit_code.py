"""failing-pre-build-phase-skips-later-phases-and-reports-the-exit-code."""
from __future__ import annotations

import json
import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-phase-skip"
_IMAGE = "aws/codebuild/standard:7.0"

# The BuildPhase phaseType enum, in the order the API reference lists it. Source:
# https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BuildPhase.html
_CANONICAL_PHASES = [
    "SUBMITTED", "QUEUED", "PROVISIONING", "DOWNLOAD_SOURCE", "INSTALL", "PRE_BUILD",
    "BUILD", "POST_BUILD", "UPLOAD_ARTIFACTS", "FINALIZING", "COMPLETED",
]


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
    """BatchGetBuilds for several ids at once, as {id: Build}; a dropped build fails loudly."""
    got = cb.batch_get_builds(ids=list(ids))
    builds = got.get("builds", [])
    by_id = {b["id"]: b for b in builds}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got "
        f"{sorted(by_id)!r} and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


def _poll_builds_terminal(cb, ids, *, timeout_s, interval_s=5.0):
    """Poll one BatchGetBuilds covering every id until all report buildComplete; raises on
    timeout. Returns {id: terminal Build}, so both builds are observed in the same call."""
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


def _phase_types(build):
    return [p.get("phaseType") for p in build.get("phases", [])]


def _succeeded_types(build):
    return {p.get("phaseType") for p in build.get("phases", [])
            if p.get("phaseStatus") == "SUCCEEDED"}


def _by_type(build):
    return {p.get("phaseType"): p for p in build.get("phases", [])}


def _context_text(phase):
    """Every context's statusCode and message on one phase, flattened to one string."""
    parts = []
    for c in (phase.get("contexts") or []):
        parts.append(c.get("statusCode") or "")
        parts.append(c.get("message") or "")
    return " ".join(parts)


def _token(n=8):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(n))


def _fingerprint(build):
    """The phase table reduced to what must not move once the build is terminal."""
    return [(p.get("phaseType"), p.get("phaseStatus"), p.get("durationInSeconds"))
            for p in build.get("phases", [])]


CHECK = "failing-pre-build-phase-skips-later-phases-and-reports-the-exit-code"
GROUP = 'buildspec-semantics'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pre_build command exiting non-zero fails exactly PRE_BUILD with the container's exit code
    in its contexts and never attempts BUILD, POST_BUILD or UPLOAD_ARTIFACTS, while an identical
    twin build runs all four phases and exports their trace tokens in order.
    """
    cb = ctx.client("codebuild")

    # Random per run, so the expected values exist only in the build's own output.
    t1, t2, t3, t4 = _token(), _token(), _token(), _token()
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

    def _spec(pre_build_extra: str) -> str:
        # buildspec 0.2: one shell for the whole build, so each phase's `export` accumulates
        # onto the previous one and the exported variable encodes the phase ORDER.
        return (
            "version: 0.2\n"
            "env:\n"
            "  exported-variables:\n"
            "    - SIM2REAL_TRACE\n"
            "phases:\n"
            "  install:\n"
            "    commands:\n"
            '      - export SIM2REAL_TRACE="${SIM2REAL_T1}"\n'
            "  pre_build:\n"
            "    commands:\n"
            '      - export SIM2REAL_TRACE="${SIM2REAL_TRACE}${SIM2REAL_T2}"\n'
            f"{pre_build_extra}"
            "  build:\n"
            "    commands:\n"
            '      - export SIM2REAL_TRACE="${SIM2REAL_TRACE}${SIM2REAL_T3}"\n'
            "  post_build:\n"
            "    commands:\n"
            '      - export SIM2REAL_TRACE="${SIM2REAL_TRACE}${SIM2REAL_T4}"\n'
        )

    # The subject differs from the control in EXACTLY one line: pre_build ends by exiting
    # with a status the container computes from two injected addends.
    spec_control = _spec("")
    spec_subject = _spec(
        "      - exit $(( SIM2REAL_EXIT_A + SIM2REAL_EXIT_B ))\n")

    name = ctx.unique_name("sim2real-behav-proj-phaseskip-")
    _create_project(cb, ctx, name, role, spec_control)

    env = [
        {"name": "SIM2REAL_T1", "value": t1, "type": "PLAINTEXT"},
        {"name": "SIM2REAL_T2", "value": t2, "type": "PLAINTEXT"},
        {"name": "SIM2REAL_T3", "value": t3, "type": "PLAINTEXT"},
        {"name": "SIM2REAL_T4", "value": t4, "type": "PLAINTEXT"},
        {"name": "SIM2REAL_EXIT_A", "value": str(addend_a), "type": "PLAINTEXT"},
        {"name": "SIM2REAL_EXIT_B", "value": str(addend_b), "type": "PLAINTEXT"},
    ]

    # Both builds are issued before either is polled: one instant, one wiring, one project.
    control = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_control,
        environmentVariablesOverride=env)
    subject = _start_build_with_stop_registered(
        cb, ctx, projectName=name, buildspecOverride=spec_subject,
        environmentVariablesOverride=env)
    assert control["id"] != subject["id"], (
        f"two StartBuild calls must mint distinct ids, both were {control['id']!r}"
    )

    final = _poll_builds_terminal(cb, [control["id"], subject["id"]], timeout_s=420)
    good = final[control["id"]]
    bad = final[subject["id"]]

    assert good["buildStatus"] == "SUCCEEDED", (
        f"the control build must SUCCEED - without it a target that fails every build would "
        f"pass the subject leg. Got {good['buildStatus']!r}; phases={_phases(good)!r}; "
        f"contexts={[p.get('contexts') for p in good.get('phases', [])]!r}"
    )
    exported = {v["name"]: v["value"]
                for v in good.get("exportedEnvironmentVariables") or []}
    expected_trace = t1 + t2 + t3 + t4
    assert exported.get("SIM2REAL_TRACE") == expected_trace, (
        f"the control's four phases must each append their own token in order, giving "
        f"{expected_trace!r}; the build exported "
        f"{exported.get('SIM2REAL_TRACE')!r} (all exported: {exported!r})"
    )
    good_ok = _succeeded_types(good)
    assert {"INSTALL", "PRE_BUILD", "BUILD", "POST_BUILD"} <= good_ok, (
        f"the control must report all four buildspec phases SUCCEEDED, its SUCCEEDED set is "
        f"{sorted(good_ok)!r}; phases={_phases(good)!r}"
    )

    assert bad["buildStatus"] == "FAILED", (
        f"a pre_build command exiting {exit_code} must yield buildStatus FAILED, got "
        f"{bad['buildStatus']!r}; phases={_phases(bad)!r}"
    )
    bad_by_type = _by_type(bad)
    pre = bad_by_type.get("PRE_BUILD")
    assert pre is not None, (
        f"no PRE_BUILD phase reported for the failing build; phases={_phases(bad)!r}"
    )
    assert pre.get("phaseStatus") == "FAILED", (
        f"PRE_BUILD must be FAILED when its own command exits {exit_code}, got "
        f"{pre.get('phaseStatus')!r}; phases={_phases(bad)!r}"
    )
    install = bad_by_type.get("INSTALL")
    assert install is not None and install.get("phaseStatus") == "SUCCEEDED", (
        f"the failure must be localised to PRE_BUILD: INSTALL ran before it and must still be "
        f"SUCCEEDED, got {install!r}; phases={_phases(bad)!r}"
    )

    # The exit code the container computed, not any literal in the buildspec.
    ctx_text = _context_text(pre)
    assert ctx_text.strip(), (
        f"a FAILED PRE_BUILD phase must carry a diagnostic context, got "
        f"contexts={pre.get('contexts')!r}"
    )
    assert str(exit_code) in ctx_text, (
        f"the failed PRE_BUILD context must report the exit status the container produced "
        f"({exit_code}, computed in-container from {addend_a}+{addend_b}, a value that appears "
        f"nowhere in the buildspec); context text was {ctx_text[:400]!r}"
    )

    # The skip rule, as a twin comparison so it holds whether the later phases are omitted
    # or merely reported non-SUCCEEDED.
    bad_ok = _succeeded_types(bad)
    assert bad_ok & {"BUILD", "POST_BUILD"} == set(), (
        f"a FAILED pre_build (default on-failure ABORT) must leave BUILD and POST_BUILD out of "
        f"the SUCCEEDED set, but the failing build reports {sorted(bad_ok)!r} as SUCCEEDED; "
        f"phases={_phases(bad)!r}"
    )
    assert bad_ok < good_ok, (
        f"the failing build's SUCCEEDED phases must be a STRICT subset of the twin control's: "
        f"subject={sorted(bad_ok)!r} vs control={sorted(good_ok)!r}"
    )

    # A default-ABORT PRE_BUILD failure aborts before BUILD, so these phases never appear at all.
    # AWS's "UPLOAD_ARTIFACTS is always attempted" guarantee covers a failing BUILD phase only.
    bad_types = _phase_types(bad)
    never_attempted = {"BUILD", "POST_BUILD", "UPLOAD_ARTIFACTS"}
    assert not (never_attempted & set(bad_types)), (
        f"a default-ABORT PRE_BUILD failure must never attempt BUILD, POST_BUILD or "
        f"UPLOAD_ARTIFACTS at all (not merely fail to succeed at them); the failing build "
        f"reported phases {bad_types!r}"
    )

    # Phase types are real enum members reported in canonical order.
    for label, build in (("control", good), ("subject", bad)):
        types = _phase_types(build)
        unknown = [t for t in types if t not in _CANONICAL_PHASES]
        assert not unknown, (
            f"the {label} build reported phase types outside the BuildPhase enum: "
            f"{unknown!r}; full list {types!r}"
        )
        positions = [_CANONICAL_PHASES.index(t) for t in types]
        assert positions == sorted(positions), (
            f"the {label} build's phases must be reported in the canonical enum order "
            f"{_CANONICAL_PHASES!r}; got {types!r}"
        )

    # A terminal build's phase table must not move under reads.
    baseline = _fingerprint(bad)
    for i in range(3):
        again = _get_builds(cb, [bad["id"]])[bad["id"]]
        assert _fingerprint(again) == baseline, (
            f"read {i + 1} of a TERMINAL build changed its phase table: baseline "
            f"{baseline!r} became {_fingerprint(again)!r}"
        )

    # A different read operation must also show both builds for this project.
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
    assert sorted(listed) == sorted([control["id"], subject["id"]]), (
        f"ListBuildsForProject must report exactly the two builds this check started for "
        f"{name!r}; it reported {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
