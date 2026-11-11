"""harness-and-endpoint-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "harness-and-endpoint-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A harness and its endpoint reach READY; DeleteHarness is refused with ConflictException and the exact message
    while the endpoint exists; UpdateHarness raises harnessVersion and the endpoint goes live on it; once the
    endpoint is deleted the harness deletes, each read then failing with its exact not-found message."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "hns")
    name = _safe_name(ctx, "sim2realhns")

    create_resp = _retry_until_role_usable(
        lambda: bac.create_harness(
            harnessName=name, executionRoleArn=role_arn, tags={"sim2real-check": CHECK}
        )
    )
    harness = create_resp["harness"]
    harness_id = harness["harnessId"]
    ctx.on_cleanup(lambda: _ac_delete_harness(bac, harness_id))

    h = _poll_until(
        lambda: bac.get_harness(harnessId=harness_id)["harness"],
        lambda r: r["status"] != "CREATING",
        timeout_s=600.0,
    )
    assert h["status"] == "READY", f"unexpected terminal status {h['status']!r}"

    endpoint_name = _safe_name(ctx, "ep")
    bac.create_harness_endpoint(
        harnessId=harness_id, endpointName=endpoint_name, tags={"sim2real-check": CHECK}
    )
    ep = _poll_until(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)["endpoint"],
        lambda r: r["status"] != "CREATING",
        timeout_s=300.0,
    )
    assert ep["status"] == "READY", f"unexpected terminal status {ep['status']!r}"

    # Nested lifecycle guard: the harness cannot be deleted while its
    # endpoint still exists.
    blocked_code, blocked_message = _error(lambda: bac.delete_harness(harnessId=harness_id))
    assert blocked_code == "ConflictException", f"expected ConflictException, got {blocked_code!r}"
    expected_blocked = (
        f"Harness {name} has endpoints that must be deleted before the harness can be deleted."
    )
    assert blocked_message == expected_blocked, (
        f"expected message {expected_blocked!r}, got {blocked_message!r}"
    )
    still_there = bac.get_harness(harnessId=harness_id)["harness"]
    assert still_there["status"] == "READY", (
        f"harness status changed to {still_there['status']!r} despite the blocked delete"
    )

    bac.update_harness(
        harnessId=harness_id,
        systemPrompt=[{"text": "You are a helpful assistant."}],
    )
    h2 = _poll_until(
        lambda: bac.get_harness(harnessId=harness_id)["harness"],
        lambda r: r["status"] != "UPDATING",
        timeout_s=300.0,
    )
    assert h2["status"] == "READY", f"unexpected terminal status {h2['status']!r}"
    assert int(h2["harnessVersion"]) > int(h["harnessVersion"]), (
        f"harnessVersion did not advance: {h['harnessVersion']!r} -> {h2['harnessVersion']!r}"
    )

    bac.update_harness_endpoint(
        harnessId=harness_id, endpointName=endpoint_name, targetVersion=h2["harnessVersion"]
    )
    ep2 = _poll_until(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)["endpoint"],
        lambda r: r["status"] != "UPDATING",
        timeout_s=300.0,
    )
    assert ep2["status"] == "READY", f"unexpected terminal status {ep2['status']!r}"
    assert ep2["liveVersion"] == h2["harnessVersion"], (
        f"endpoint liveVersion {ep2['liveVersion']!r} != target harnessVersion {h2['harnessVersion']!r}"
    )

    bac.delete_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)
    ep_code, ep_message = _wait_rejected(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name),
        timeout_s=90.0,
    )
    assert ep_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after endpoint delete, got {ep_code!r}"
    )
    expected_ep = f"Endpoint {endpoint_name} not found for harness {harness_id}."
    assert ep_message == expected_ep, f"expected message {expected_ep!r}, got {ep_message!r}"

    # Positive control: with the endpoint gone, deletion succeeds. A harness takes
    # minutes to delete, longer than its endpoint, so the wait allows 300 s.
    bac.delete_harness(harnessId=harness_id)
    h_code, h_message = _wait_rejected(lambda: bac.get_harness(harnessId=harness_id), timeout_s=300.0)
    assert h_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after harness delete, got {h_code!r}"
    )
    expected_h = f"Agent with name {harness_id} not found."
    assert h_message == expected_h, f"expected message {expected_h!r}, got {h_message!r}"


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out transitional statuses and then for the resource to be gone.
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


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _wait_rejected(fn, *, timeout_s, interval_s=3.0):
    """Retry ``fn`` until it is rejected and return its (code, message); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:40]


def _create_agentcore_execution_role(ctx, name_hint):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-bac-{name_hint}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
