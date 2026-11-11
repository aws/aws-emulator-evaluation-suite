"""concurrent-put-resource-policy-optimistic-lock."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-resource-policy-optimistic-lock"
GROUP = 'concurrency'
SERVICES = ['xray']


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _account_id(ctx, xr):
    """Derive the caller's account ID from a group ARN (X-Ray resource policies validate the
    principal exists, so a placeholder account is rejected). Stays within the service under
    test rather than relying on STS. Creates a group if none exists, registering its cleanup."""
    arn = None
    for group in xr.get_groups().get("Groups", []):
        if group.get("GroupARN"):
            arn = group["GroupARN"]
            break
    if not arn:
        name = ctx.unique_name("sim2real-behav-xray-acct-")
        arn = xr.create_group(GroupName=name, FilterExpression='service("default")')["Group"]["GroupARN"]
        ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))
    # arn:aws:xray:<region>:<account-id>:group/<name>/<id>
    return arn.split(":")[4]


def _policy_document(account_id, sid=None):
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "xray:PutTraceSegments",
        "Resource": "*",
    }
    if sid:
        statement["Sid"] = sid
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing PutResourcePolicy calls that all pin the same base PolicyRevisionId serialize:
    exactly one wins, the rest fail with InvalidPolicyRevisionIdException."""
    xr = ctx.client("xray")
    account_id = _account_id(ctx, xr)
    name = ctx.unique_name("sim2real-behav-xray-policy-")
    base = xr.put_resource_policy(
        PolicyName=name, PolicyDocument=_policy_document(account_id)
    )["ResourcePolicy"]
    ctx.on_cleanup(lambda: xr.delete_resource_policy(PolicyName=name))
    base_revision = base["PolicyRevisionId"]

    def attempt(i):
        return xr.put_resource_policy(
            PolicyName=name,
            PolicyDocument=_policy_document(account_id, sid=f"racer{i}"),
            PolicyRevisionId=base_revision,
        )

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(5)], timeout_s=90)
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} (codes={codes})"
    assert all(c == "InvalidPolicyRevisionIdException" for c in codes), codes
    expected = f"Another concurrent request has modified the resource policy {name}"
    messages = [r.response["Error"].get("Message") for r in results if isinstance(r, ClientError)]
    assert all(m == expected for m in messages), messages

    winner = next(r for r in results if not isinstance(r, BaseException))["ResourcePolicy"]
    listed = xr.list_resource_policies().get("ResourcePolicies", [])
    persisted = next((p for p in listed if p["PolicyName"] == name), None)
    assert persisted is not None, f"policy missing from ListResourcePolicies: {listed}"
    assert persisted["PolicyRevisionId"] == winner["PolicyRevisionId"], (
        f"persisted revision {persisted['PolicyRevisionId']!r} != winner's "
        f"{winner['PolicyRevisionId']!r} (some racer other than the reported winner won)"
    )
    assert persisted["PolicyRevisionId"] != base_revision
    assert json.loads(persisted["PolicyDocument"]) == json.loads(winner["PolicyDocument"]), (
        f"persisted document does not match the winning racer's document: {persisted['PolicyDocument']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
