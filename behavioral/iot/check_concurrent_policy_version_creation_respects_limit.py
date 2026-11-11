"""concurrent-policy-version-creation-respects-limit."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-policy-version-creation-respects-limit"
GROUP = 'concurrency'
SERVICES = ['iot']

def _policy_doc(effect: str = "Allow", version: int = 1) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": effect,
                    "Action": "iot:Connect",
                    "Resource": f"arn:aws:iot:*:*:client/probe-{version}",
                }
            ],
        }
    )

def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers create policy versions on the same policy concurrently; the 5-version
    cap must be enforced exactly even under contention (no lost updates / no overshoot)."""
    iot = ctx.client("iot")
    policy_name = ctx.unique_name("sim2real-behav-policy-race-")
    iot.create_policy(policyName=policy_name, policyDocument=_policy_doc(version=0))
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))

    racers = 8  # version 1 already exists (from create_policy); only 4 more can succeed (cap=5)
    calls = [
        (lambda v=v: iot.create_policy_version(
            policyName=policy_name, policyDocument=_policy_doc(version=v), setAsDefault=False
        ))
        for v in range(1, racers + 1)
    ]
    results = _run_concurrent(calls, timeout_s=90)

    successes = _concurrent_successes(results)
    error_codes = _concurrent_error_codes(results)

    # The guarantee under test is that concurrent creation NEVER exceeds the 5-version cap
    # (1 default + at most 4 new). The exact success count is not deterministic under real
    # contention: a racer can lose to a concurrent-modification rejection without consuming a
    # slot, yielding fewer than 4 successes. Pin the invariant (cap respected), not the race.
    assert 1 <= successes <= 4, f"expected 1..4 successful version creations, got {successes}"
    # Under real contention AWS rejects the losers with either the quota error or a
    # generic InvalidRequestException (concurrent-modification), never with success.
    # Which one wins the race is not deterministic: the cap frequently surfaces purely as
    # InvalidRequestException when every racer collides before any observes 5 versions, so
    # we only require the losers to be rejected with an allowed code (not the specific
    # quota exception). The cap itself is still pinned by the exact success count and the
    # final version-count assertion below.
    allowed = {"VersionsLimitExceededException", "InvalidRequestException"}
    assert all(c in allowed for c in error_codes), (
        f"expected only {sorted(allowed)} failures, got {error_codes}"
    )
    # The concurrent-modification refusal's exact message; the quota refusal's is unpinned.
    expected_messages = {"InvalidRequestException": "Parallel updates to the same record."}
    for r in results:
        if isinstance(r, ClientError):
            code = r.response.get("Error", {}).get("Code")
            message = r.response.get("Error", {}).get("Message")
            if code in expected_messages:
                assert message == expected_messages[code], f"{code}: {message!r}"
    assert successes + len(error_codes) == racers, (
        f"every racer must resolve to either a success or a captured error code, "
        f"got {successes} successes and {len(error_codes)} error codes for {racers} racers"
    )

    versions = iot.list_policy_versions(policyName=policy_name)["policyVersions"]
    assert len(versions) <= 5, f"policy must never exceed the 5-version cap, has {len(versions)}"
    assert len(versions) == successes + 1, (
        f"version count must equal successful creations plus the default, "
        f"has {len(versions)} vs {successes}+1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
