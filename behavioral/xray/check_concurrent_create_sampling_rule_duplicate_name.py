"""concurrent-create-sampling-rule-duplicate-name."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-sampling-rule-duplicate-name"
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


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": random.randint(1, 9999),
        "FixedRate": 0.05,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }
    rule.update(overrides)
    return rule


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateSamplingRule with the identical RuleName serializes: exactly one create wins,
    the rest are rejected with InvalidRequestException, and the rule exists exactly once."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"))
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule["RuleName"]))

    def attempt():
        return xr.create_sampling_rule(
            SamplingRule=dict(rule), Tags=[{"Key": "sim2real", "Value": CHECK}]
        )

    results = _run_concurrent([attempt for _ in range(5)], timeout_s=90)
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} (codes={codes})"
    assert all(c == "InvalidRequestException" for c in codes), codes
    # The suffix is the winning rule's internalId, which no response exposes.
    prefix = "A resource with the same resourceName but a different internalId already exists: "
    messages = [r.response["Error"].get("Message") for r in results if isinstance(r, ClientError)]
    assert all((m or "").startswith(prefix) for m in messages), messages

    all_rules = xr.get_sampling_rules()["SamplingRuleRecords"]
    matched = [r for r in all_rules if r["SamplingRule"]["RuleName"] == rule["RuleName"]]
    assert len(matched) == 1, f"expected rule to exist exactly once, got {len(matched)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
