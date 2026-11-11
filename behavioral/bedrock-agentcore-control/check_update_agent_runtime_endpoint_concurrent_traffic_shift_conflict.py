"""update-agent-runtime-endpoint-concurrent-traffic-shift-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-agent-runtime-endpoint-concurrent-traffic-shift-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]
_CONFLICT_MESSAGE = (
    "The endpoint is currently being modified by another operation. Current status: UPDATING. Wait and try again."
)

_CONTAINER_URI = "public.ecr.aws/lambda/python:3.12"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent traffic-shift UpdateAgentRuntimeEndpoint calls (versions 2 and 3): each is
    applied or refused with ConflictException, and the endpoint settles on the version of an
    accepted call, never on a refused call's version."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    runtime_name = _safe_agentcore_name(ctx, "sim2realrt")
    create_resp = _create_agent_runtime_with_role_retry(
        bac,
        timeout_s=_wait_s(ctx, 120),
        agentRuntimeName=runtime_name,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": _CONTAINER_URI}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    runtime_id = create_resp["agentRuntimeId"]
    version1 = create_resp["agentRuntimeVersion"]
    ctx.on_cleanup(lambda: bac.delete_agent_runtime(agentRuntimeId=runtime_id))
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    assert bac.get_agent_runtime(agentRuntimeId=runtime_id)["status"] == "READY"

    update2 = bac.update_agent_runtime(
        agentRuntimeId=runtime_id,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": _CONTAINER_URI}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        description="v2",
    )
    version2 = update2["agentRuntimeVersion"]
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] in ("READY", "UPDATE_FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    assert bac.get_agent_runtime(agentRuntimeId=runtime_id)["status"] == "READY"

    update3 = bac.update_agent_runtime(
        agentRuntimeId=runtime_id,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": _CONTAINER_URI}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        description="v3",
    )
    version3 = update3["agentRuntimeVersion"]
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] in ("READY", "UPDATE_FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    assert bac.get_agent_runtime(agentRuntimeId=runtime_id)["status"] == "READY"
    assert len({version1, version2, version3}) == 3, "expected three distinct runtime versions"

    endpoint_name = _safe_agentcore_name(ctx, "sim2realep")
    bac.create_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, name=endpoint_name, agentRuntimeVersion=version1,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_endpoint(bac, runtime_id, endpoint_name))
    _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    assert bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)["status"] == "READY"

    def _shift(version):
        return lambda: bac.update_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=endpoint_name, agentRuntimeVersion=version
        )

    results = _race([_shift(version2), _shift(version3)])
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented traffic-shift refusal: {code!r} ({message!r})"
            assert message == _CONFLICT_MESSAGE, f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"
    accepted = {v for (ok, _), v in zip(results, (version2, version3)) if ok}
    assert accepted, f"both traffic shifts were refused: {results}"

    final = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] == "READY",
        timeout_s=_wait_s(ctx, 180),
    )
    assert final["liveVersion"] in accepted, (
        f"endpoint live version {final['liveVersion']!r} is not an accepted shift {sorted(accepted)}: {final}"
    )
    assert final.get("targetVersion", final["liveVersion"]) == final["liveVersion"], (
        f"endpoint is READY but its target and live versions differ: {final}"
    )


def _safe_agentcore_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _create_agent_runtime_with_role_retry(bac, timeout_s=120.0, interval_s=5.0, **kwargs):
    """CreateAgentRuntime validates the execution role's trust policy synchronously; a role
    created moments ago can still fail that check while IAM propagates it. Retry on that
    specific ValidationException instead of treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.create_agent_runtime(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "Role validation failed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_agentcore_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bac-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


def _delete_endpoint(bac, runtime_id, endpoint_name, timeout_s=180.0):
    """Delete the endpoint once it leaves UPDATING and wait until it is gone, so the runtime delete
    that follows succeeds."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bac.delete_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    while True:
        try:
            bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name!r} still present {timeout_s}s after delete")
        time.sleep(5.0)


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
