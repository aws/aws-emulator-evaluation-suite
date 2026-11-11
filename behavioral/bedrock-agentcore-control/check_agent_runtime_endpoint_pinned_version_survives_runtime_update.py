"""agent-runtime-endpoint-pinned-version-survives-runtime-update."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

# GetAgentRuntimeEndpoint/
# UpdateAgentRuntimeEndpoint omit `targetVersion` once an endpoint is at rest (status READY,
# nothing pending) — the Smithy model marks it optional, and AWS only populates it while a
# promotion is in flight. Every read below treats a missing `targetVersion` as equal to
# `liveVersion` rather than subscripting it directly; `liveVersion` is always present and is
# asserted on its own in every case, so this does not weaken what is checked. The DEFAULT
# endpoint auto-advance is near-instantaneous — the very first poll already
# observes it — so the calibrated absence window collapses to its 15s floor.

CHECK = "agent-runtime-endpoint-pinned-version-survives-runtime-update"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A named AgentRuntimeEndpoint pinned to an explicit runtime version stays on that
    version when the runtime publishes a newer one — proven against the DEFAULT endpoint,
    which auto-advances in the same instant — and moves only on explicit promotion."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "pin")
    artifacts = _code_artifact_factory(ctx)

    runtime_name = _pattern_safe_name(ctx, "sim2realpinrt")
    created = _retry_until_role_usable(
        lambda: bac.create_agent_runtime(
            agentRuntimeName=runtime_name,
            agentRuntimeArtifact=artifacts("v1"),
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
        )
    )
    runtime_id = created["agentRuntimeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_runtime(bac, runtime_id))

    v1 = created["agentRuntimeVersion"]
    assert v1 == "1", (
        f"expected a brand-new runtime to be version '1', got {v1!r} for runtime {runtime_id}"
    )
    settled = _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        "the new runtime to leave CREATING",
        timeout_s=180.0,
    )
    assert settled["status"] == "READY", (
        f"expected runtime status READY after create, got {settled['status']!r} "
        f"reason={settled.get('failureReason')!r}"
    )

    # The subject: a NAMED endpoint pinned to an EXPLICIT version.
    pinned_name = _pattern_safe_name(ctx, "sim2realpinned")
    bac.create_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, name=pinned_name, agentRuntimeVersion=v1
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: bac.delete_agent_runtime_endpoint(
                agentRuntimeId=runtime_id, endpointName=pinned_name
            )
        )
    )
    pinned0 = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=pinned_name
        ),
        lambda r: r["status"] != "CREATING",
        "the pinned endpoint to leave CREATING",
        timeout_s=180.0,
    )
    assert pinned0["status"] == "READY", (
        f"expected pinned endpoint READY, got {pinned0['status']!r} "
        f"reason={pinned0.get('failureReason')!r}"
    )
    assert pinned0.get("targetVersion", pinned0.get("liveVersion")) == v1, (
        f"expected pinned endpoint targetVersion=={v1!r}, got {pinned0.get('targetVersion')!r}"
    )
    assert pinned0["liveVersion"] == v1, (
        f"expected pinned endpoint liveVersion=={v1!r}, got {pinned0['liveVersion']!r}"
    )

    # The twin control, read at the same instant on the same runtime: the DEFAULT endpoint,
    # which the docs say tracks the latest version automatically. An absent DEFAULT is a
    # failure — the docs promise it exists from the moment the runtime is created.
    default0 = bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName="DEFAULT")
    assert default0.get("targetVersion", default0.get("liveVersion")) == v1, (
        f"expected the DEFAULT endpoint to start on {v1!r}, got {default0.get('targetVersion')!r}"
    )

    # Publish a new version by changing the artifact.
    updated = bac.update_agent_runtime(
        agentRuntimeId=runtime_id,
        agentRuntimeArtifact=artifacts("v2"),
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
    )
    v2 = updated["agentRuntimeVersion"]
    # Derivation rule, not a literal: the new version is the integer successor of the old one.
    assert int(v2) == int(v1) + 1, (
        f"expected UpdateAgentRuntime to mint the successor of version {v1!r}, got {v2!r}"
    )
    runtime_after = _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "UPDATING",
        "the runtime to leave UPDATING after publishing a new version",
        timeout_s=180.0,
    )
    assert runtime_after["status"] == "READY", (
        f"expected runtime READY after update, got {runtime_after['status']!r} "
        f"reason={runtime_after.get('failureReason')!r}"
    )
    assert runtime_after["agentRuntimeVersion"] == v2, (
        f"expected GetAgentRuntime to report the new version {v2!r}, "
        f"got {runtime_after['agentRuntimeVersion']!r}"
    )

    # Independent read through a different operation: both versions must now be listed.
    listed = _list_runtime_versions(bac, runtime_id)
    assert {v1, v2} <= listed, (
        f"expected ListAgentRuntimeVersions to contain both {v1!r} and {v2!r}, got {sorted(listed)}"
    )

    # Measure the twin control's latency L on the same wiring, in the same run: how long the
    # AUTO-advancing endpoint takes to reach the new version. This calibrates the window over
    # which the pinned endpoint's absence-of-movement is meaningful.
    t0 = time.monotonic()
    default_final = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName="DEFAULT"),
        lambda r: r.get("liveVersion") == v2 and r["status"] == "READY",
        f"the DEFAULT endpoint to auto-advance to version {v2}",
        timeout_s=180.0,
    )
    latency_s = time.monotonic() - t0
    assert default_final["liveVersion"] == v2, (
        f"expected the auto-advanced DEFAULT endpoint liveVersion=={v2!r}, "
        f"got {default_final['liveVersion']!r}"
    )

    # Hold the pinned endpoint's absence-of-movement for >= 3L (floor 15s) and require at least
    # three consecutive IDENTICAL reads: a target that is merely slow fails
    # the control leg above, and a target that mutates the pin on a read fails here.
    hold_s = max(3.0 * latency_s, 15.0)
    observations = []
    hold_deadline = time.monotonic() + hold_s
    while time.monotonic() < hold_deadline or len(observations) < 3:
        state = bac.get_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=pinned_name
        )
        assert state.get("targetVersion", state.get("liveVersion")) == v1, (
            f"pinned endpoint moved off {v1!r}: targetVersion={state.get('targetVersion')!r} "
            f"after the DEFAULT endpoint advanced to {v2!r} in {latency_s:.1f}s"
        )
        # Second independent observable of the same absence.
        assert state["liveVersion"] == v1, (
            f"pinned endpoint's deployed code moved off {v1!r}: "
            f"liveVersion={state['liveVersion']!r} while DEFAULT is on {v2!r}"
        )
        assert state["status"] == "READY", (
            f"pinned endpoint left READY without being asked to: {state['status']!r} "
            f"reason={state.get('failureReason')!r}"
        )
        observations.append((state.get("targetVersion"), state["liveVersion"], state["status"]))
        time.sleep(5.0)
    assert len(set(observations)) == 1, (
        f"expected the pinned endpoint to be frozen across {len(observations)} reads over "
        f"{hold_s:.0f}s, got distinct observations {sorted(set(observations))}"
    )

    # Now DEMAND the move. A target that "pins" by having no versioning at all passes the leg
    # above and fails here.
    bac.update_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, endpointName=pinned_name, agentRuntimeVersion=v2
    )
    promoted = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=pinned_name
        ),
        lambda r: r["status"] not in ("UPDATING", "CREATING"),
        f"the pinned endpoint to settle after promotion to version {v2}",
        timeout_s=180.0,
    )
    assert promoted["status"] == "READY", (
        f"expected promoted endpoint READY, got {promoted['status']!r} "
        f"reason={promoted.get('failureReason')!r}"
    )
    assert promoted.get("targetVersion", promoted.get("liveVersion")) == v2, (
        f"expected promoted endpoint targetVersion=={v2!r}, got {promoted.get('targetVersion')!r}"
    )
    assert promoted["liveVersion"] == v2, (
        f"expected promoted endpoint liveVersion=={v2!r}, got {promoted['liveVersion']!r}"
    )

    # Promotion of one endpoint must not perturb the other.
    default_end = bac.get_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, endpointName="DEFAULT"
    )
    assert default_end.get("targetVersion", default_end.get("liveVersion")) == v2, (
        f"promoting {pinned_name} moved DEFAULT to {default_end.get('targetVersion')!r}, "
        f"expected it to stay on {v2!r}"
    )
    assert default_end["liveVersion"] == v2, (
        f"promoting {pinned_name} moved DEFAULT's liveVersion to "
        f"{default_end['liveVersion']!r}, expected it to stay on {v2!r}"
    )



def _poll_until(probe, predicate, reason, timeout_s=180.0, interval_s=5.0):
    """Bounded retry with a stated reason; RAISES on timeout (never returns the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _list_runtime_versions(bac, runtime_id):
    versions = set()
    next_token = None
    while True:
        kwargs = {"agentRuntimeId": runtime_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = bac.list_agent_runtime_versions(**kwargs)
        for item in page["agentRuntimes"]:
            versions.add(item["agentRuntimeVersion"])
        next_token = page.get("nextToken")
        if not next_token:
            return versions


def _pattern_safe_name(ctx, prefix):
    """AgentRuntimeName / EndpointName are ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "a" + safe
    return safe[:48]


def _safe_bucket_name(ctx, prefix):
    raw = ctx.unique_name(prefix).lower()
    cleaned = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw).strip("-")
    return cleaned[:63]


def _code_artifact_factory(ctx):
    """Returns fn(tag) -> a codeConfiguration artifact backed by a real S3 object.

    CreateAgentRuntime actively validates a containerConfiguration ECR URI. The bucket is created
    once and reused across tags so both versions come from one bucket.
    """
    s3 = ctx.client("s3")
    holder = {}

    def artifact(tag):
        if "bucket" not in holder:
            bucket = _safe_bucket_name(ctx, "sim2real-bacpin-code")
            if ctx.region == "us-east-1":
                s3.create_bucket(Bucket=bucket)
            else:
                s3.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={"LocationConstraint": ctx.region},
                )
            s3.put_bucket_tagging(
                Bucket=bucket,
                Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
            )
            ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
            holder["bucket"] = bucket
        bucket = holder["bucket"]

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "main.py",
                f"def handler(event, context):\n    return {{'variant': {tag!r}}}\n",
            )
        key = f"sim2real/{CHECK}/{tag}/deployment_package.zip"
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=buf.getvalue(),
            Tagging=f"sim2real={CHECK}",
        )
        ctx.on_cleanup(lambda: _safe_delete(lambda: s3.delete_object(Bucket=bucket, Key=key)))
        return {
            "codeConfiguration": {
                "code": {"s3": {"bucket": bucket, "prefix": key}},
                "runtime": "PYTHON_3_12",
                "entryPoint": ["main.py"],
            }
        }

    return artifact


def _empty_and_delete_bucket(s3, bucket):
    try:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            page = s3.list_objects_v2(**kwargs)
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_agentcore_execution_role(ctx, hint):
    """Create-or-adopt is not needed: the role name is unique per run and this check creates it."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-bacpin-{hint}-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _retry_until_role_usable(fn, timeout_s=120.0, interval_s=6.0):
    """A freshly created role's trust policy is eventually consistent; CreateAgentRuntime
    reports that as ValidationException 'Role validation failed'. Retry only that."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("AccessDeniedException", "ValidationException") and (
                "Role validation failed" in message or "role" in message.lower()
            ):
                last = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s; last error={last}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "NoSuchEntity",
            "NoSuchKey",
        ):
            raise


def _best_effort_delete_runtime(bac, runtime_id):
    """DeleteAgentRuntime conflicts while endpoints are still being removed; retry the
    conflict on a bounded deadline, then let the final attempt raise."""
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            bac.delete_agent_runtime(agentRuntimeId=runtime_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5.0)
    bac.delete_agent_runtime(agentRuntimeId=runtime_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
