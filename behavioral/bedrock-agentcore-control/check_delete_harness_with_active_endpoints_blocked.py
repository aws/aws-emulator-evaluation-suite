"""delete-harness-with-active-endpoints-blocked."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-harness-with-active-endpoints-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteHarness is rejected with ConflictException while a
    HarnessEndpoint still exists, and a harness with no endpoints can still be
    deleted (positive control)."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    harness_name = _alnum(ctx, "s2rHarn", 40)
    harness = _create_harness_with_role_retry(
        bac,
        harnessName=harness_name,
        executionRoleArn=role_arn,
        model={"bedrockModelConfig": {"modelId": "amazon.nova-lite-v1:0"}},
    )
    harness_id = harness["harness"]["harnessId"]
    ctx.on_cleanup(lambda: _ac_delete_harness(bac, harness_id))

    def _version_ready():
        versions = bac.list_harness_versions(harnessId=harness_id)["harnessVersions"]
        v1 = next((v for v in versions if v["harnessVersion"] == "1"), None)
        return v1

    version_state = _poll(
        _version_ready,
        lambda v: v is not None and v["status"] not in ("CREATING",),
        timeout_s=700.0,
        interval_s=5.0,
    )
    assert (
        version_state is not None and version_state["status"] == "READY"
    ), f"harness version 1 never reached READY: {version_state!r}"

    ep_name = _alnum(ctx, "s2rHarnEp", 48)
    bac.create_harness_endpoint(harnessId=harness_id, endpointName=ep_name, targetVersion="1")
    _poll(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=ep_name),
        lambda r: r["endpoint"]["status"] != "CREATING",
        timeout_s=300.0,
    )

    code, message = _error_detail(lambda: bac.delete_harness(harnessId=harness_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"Harness {harness_name} has endpoints that must be deleted before the harness can be deleted."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = bac.get_harness(harnessId=harness_id)
    assert still["harness"]["status"] != "DELETING", "harness entered DELETING despite the blocked call"

    # Positive control: a harness with no endpoints deletes cleanly. Rather
    # than pre-polling status (creation can be slow and unpredictable), retry
    # the delete itself until it stops bouncing off the transient
    # "still CREATING" ConflictException.
    harness2_name = _alnum(ctx, "s2rHarn2", 40)
    harness2 = _create_harness_with_role_retry(
        bac,
        harnessName=harness2_name,
        executionRoleArn=role_arn,
        model={"bedrockModelConfig": {"modelId": "amazon.nova-lite-v1:0"}},
    )
    harness_id2 = harness2["harness"]["harnessId"]
    ctx.on_cleanup(lambda: _ac_delete_harness(bac, harness_id2))
    del_resp = _retry_conflict(lambda: bac.delete_harness(harnessId=harness_id2), timeout_s=700.0)
    assert del_resp["harness"]["status"] == "DELETING", "expected the empty harness delete to be accepted"

    # Independent terminal read: the delete call's own response is not enough, since it only
    # echoes what was requested. Confirm the harness actually disappears at the destination.
    gone_code, gone_message = _poll_gone(lambda: bac.get_harness(harnessId=harness_id2), timeout_s=400.0)
    assert gone_code == "ResourceNotFoundException", f"expected the deleted harness to 404, got {gone_code!r}"
    expected_gone = f"Agent with name {harness_id2} not found."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_harness(control, harness_id):
    """Endpoints first (DeleteHarness is refused while one exists); the harness then takes its
    DEFAULT endpoint, managed memory and runtime with it -- none of those can be deleted directly."""
    try:
        pages = control.get_paginator("list_harness_endpoints").paginate(harnessId=harness_id)
        endpoint_names = [
            e["endpointName"] for page in pages for e in page.get("endpoints", []) if e["endpointName"] != "DEFAULT"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for endpoint_name in endpoint_names:
        _ac_delete_and_wait(
            lambda: control.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)["endpoint"]["status"],
            lambda: control.delete_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name),
            what=f"harness endpoint {endpoint_name}",
        )
    _ac_delete_and_wait(
        lambda: control.get_harness(harnessId=harness_id)["harness"]["status"],
        lambda: control.delete_harness(harnessId=harness_id),
        what=f"harness {harness_id}",
    )


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_]", "", raw)
    return name[:maxlen]


def _kebab(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9-]", "-", raw).strip("-")
    return name[:maxlen]


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=400.0, interval_s=5.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_harness_with_role_retry(bac, timeout_s=120.0, interval_s=5.0, **kwargs):
    """CreateHarness validates the execution role's trust policy synchronously; a role
    created moments ago can still fail that check while IAM propagates it. Retry on that
    specific ValidationException instead of treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.create_harness(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "Role validation failed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _retry_conflict(fn, timeout_s=120.0, interval_s=5.0):
    """Retry an operation that transiently fails with ConflictException while
    the target resource is still finishing an earlier CREATING transition."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _create_agentcore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _kebab(ctx, "sim2real-bac-role", 64)
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="AllowBedrockInvoke", PolicyDocument=json.dumps(invoke_policy)
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="AllowBedrockInvoke")))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
