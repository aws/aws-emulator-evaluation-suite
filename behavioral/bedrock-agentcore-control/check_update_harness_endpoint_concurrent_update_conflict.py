"""update-harness-endpoint-concurrent-update-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-harness-endpoint-concurrent-update-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateHarnessEndpoint calls with different descriptions: each is applied or
    refused with ConflictException, and the endpoint settles on exactly one accepted call's
    description, never a refused call's or a merge."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    harness = _create_harness_with_role_retry(
        bac, _safe_name(ctx, "sim2realh"), role_arn, timeout_s=_wait_s(ctx, 120)
    )
    harness_id = harness["harness"]["harnessId"]
    ctx.on_cleanup(lambda: _ac_delete_harness(bac, harness_id))
    _poll_until(
        lambda: bac.get_harness(harnessId=harness_id),
        lambda r: r["harness"]["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 300),
    )
    harness_status = bac.get_harness(harnessId=harness_id)["harness"]["status"]
    assert harness_status == "READY", f"expected harness READY, got {harness_status!r}"

    endpoint_name = _safe_name(ctx, "sim2realhep")
    bac.create_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)
    _poll_until(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name),
        lambda r: r["endpoint"]["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    endpoint_status = bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)["endpoint"]["status"]
    assert endpoint_status == "READY", f"expected endpoint READY, got {endpoint_status!r}"

    def _updater(desc):
        return lambda: bac.update_harness_endpoint(
            harnessId=harness_id, endpointName=endpoint_name, description=desc
        )

    results = _race([_updater("edit-a"), _updater("edit-b")])
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented UpdateHarnessEndpoint refusal: {code!r} ({message!r})"
            expected = f"Cannot update endpoint {endpoint_name} while it is UPDATING. Wait and try again."
            assert message == expected, f"ConflictException message {message!r}, expected {expected!r}"
    accepted = {d for (ok, _), d in zip(results, ("edit-a", "edit-b")) if ok}
    assert accepted, f"both UpdateHarnessEndpoint callers were refused: {results}"

    final = _poll_until(
        lambda: bac.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name),
        lambda r: r["endpoint"]["status"] == "READY",
        timeout_s=_wait_s(ctx, 120),
    )
    assert final["endpoint"].get("description") in accepted, (
        f"description {final['endpoint'].get('description')!r} is not an accepted update {sorted(accepted)}: {final}"
    )


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


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _create_harness_with_role_retry(bac, name, role_arn, timeout_s=120.0, interval_s=5.0):
    """CreateHarness validates the execution role's trust policy synchronously; a role
    created moments ago can still fail that check while IAM propagates it. Retry on that
    specific ValidationException instead of treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.create_harness(harnessName=name, executionRoleArn=role_arn)
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


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
