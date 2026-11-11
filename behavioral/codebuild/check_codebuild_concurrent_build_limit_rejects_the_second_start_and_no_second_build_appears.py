"""codebuild-concurrent-build-limit-rejects-the-second-start-and-no-second-build-appears."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-concurrency-limit"
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


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete; None if the deadline passes first."""
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

CHECK = "codebuild-concurrent-build-limit-rejects-the-second-start-and-no-second-build-appears"
GROUP = 'quota'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With concurrentBuildLimit=1, StartBuild while another build is in BUILD is
    AccountLimitExceededException with no new build record; the same call succeeds once it ends.
    """
    cb = ctx.client("codebuild")

    sleeper = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo sim2real-holding-the-only-slot\n"
        "      - sleep 30\n"
    )
    name = ctx.unique_name("sim2real-behav-proj-lim-")
    _create_project(cb, ctx, name, _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"}]), sleeper, concurrentBuildLimit=1)

    def _ids_for_project():
        """Every build id of this project, paginated: page one is not a bound."""
        ids = []
        token = None
        while True:
            resp = cb.list_builds_for_project(
                projectName=name, **({"nextToken": token} if token else {}))
            ids.extend(resp.get("ids", []))
            token = resp.get("nextToken")
            if not token:
                return sorted(ids)

    first = _start_build_with_stop_registered(cb, ctx, projectName=name)

    # The barrier is the occupying build reaching its BUILD phase: only then is the single
    # slot demonstrably held, so a rejection cannot be confused with "not started yet".
    deadline = time.monotonic() + 180
    first_phase = None
    while time.monotonic() < deadline:
        live = cb.batch_get_builds(ids=[first["id"]])["builds"][0]
        first_phase = live.get("currentPhase")
        if first_phase == "BUILD":
            break
        assert not live.get("buildComplete"), (
            f"the occupying build finished before it held the slot: {_phases(live)!r}"
        )
        time.sleep(2)
    assert first_phase == "BUILD", (
        f"build 1 was in phase {first_phase!r} rather than BUILD, so the concurrency slot "
        f"was not demonstrably occupied"
    )

    ids_before = _ids_for_project()

    second = None
    code = None
    message = ""
    try:
        second = cb.start_build(projectName=name)["build"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message") or ""
    if second is not None:
        # It wrongly succeeded: the build exists and must be stopped, not leaked.
        ctx.on_cleanup(lambda: _stop(cb, second["id"]))
    assert code == "AccountLimitExceededException", (
        f"expected AccountLimitExceededException at concurrentBuildLimit=1, got {code!r}: "
        f"{message!r}; the second StartBuild returned {second!r}"
    )
    assert message == (
        "Concurrent build limit exceeded. This build project has a limit of 1 concurrent "
        "build(s). Start the build again after other builds are complete, or edit project "
        "configuration."
    ), f"the rejection message differs: {message!r}"

    ids_after = _ids_for_project()
    assert ids_after == ids_before, (
        f"a build record appeared for the rejected start: "
        f"{sorted(set(ids_after) - set(ids_before))!r}"
    )

    first_final = _poll_build_terminal(cb, first["id"], timeout_s=240)
    assert first_final is not None, f"build {first['id']!r} never reported buildComplete"
    assert first_final["buildStatus"] == "SUCCEEDED", (
        f"the occupying build was {first_final['buildStatus']!r}; phases="
        f"{_phases(first_final)!r}"
    )

    third = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n"
                          "      - echo sim2real-slot-free\n")
    third_final = _poll_build_terminal(cb, third["id"], timeout_s=240)
    assert third_final is not None, f"build {third['id']!r} never reported buildComplete"
    assert third_final["buildStatus"] == "SUCCEEDED", (
        f"a start issued after the occupying build finished was "
        f"{third_final['buildStatus']!r}; phases={_phases(third_final)!r}"
    )
    assert third["id"] != first["id"], "two StartBuild calls must mint distinct build ids"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
