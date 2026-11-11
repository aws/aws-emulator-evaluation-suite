"""untag-resource-concurrent-modification."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-concurrent-modification"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_NON_CONCURRENT_ERROR_CODES = {
    # Any code OTHER than these on a racing writer is a genuine bug/regression,
    # not an expected contention outcome, and must fail the check.
    "ConcurrentModificationException",
    "ConflictException",
}


def _dashboard_body(marker: str) -> str:
    return json.dumps(
        {
            "widgets": [
                {
                    "type": "text",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 3,
                    "properties": {"markdown": marker},
                }
            ]
        }
    )


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


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UntagResource calls removing different keys of one dashboard fail only with
    ConcurrentModificationException/ConflictException, every key reported removed is gone, and every
    key whose removal failed is still present."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-untagcc-")
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_dashboard_body("untag-race"))
    ctx.on_cleanup(lambda _n=dash_name: cw.delete_dashboards(DashboardNames=[_n]))
    dash_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dash_name}"

    n = 10
    tag_keys = [f"probe{i}" for i in range(n)]
    cw.tag_resource(ResourceARN=dash_arn, Tags=[{"Key": k, "Value": "x"} for k in tag_keys])

    before = {t["Key"] for t in cw.list_tags_for_resource(ResourceARN=dash_arn).get("Tags", [])}
    assert set(tag_keys) <= before, f"setup failed to apply all tags, got {before}"

    def untag(k: str):
        return cw.untag_resource(ResourceARN=dash_arn, TagKeys=[k])

    results = _run_concurrent([lambda k=k: untag(k) for k in tag_keys], timeout_s=60)

    codes = _concurrent_error_codes(results)
    bad_codes = [c for c in codes if c not in _NON_CONCURRENT_ERROR_CODES]
    assert not bad_codes, f"unexpected error code(s) from concurrent UntagResource writers: {bad_codes}"

    remaining = {t["Key"] for t in cw.list_tags_for_resource(ResourceARN=dash_arn).get("Tags", [])}
    reported_removed = {k for k, r in zip(tag_keys, results) if not isinstance(r, BaseException)}
    reported_failed = {k for k, r in zip(tag_keys, results) if isinstance(r, BaseException)}

    still_present_but_reported_removed = reported_removed & remaining
    assert not still_present_but_reported_removed, (
        f"keys reported successfully removed but still present (half-deleted/inconsistent "
        f"tag state): {still_present_but_reported_removed}"
    )
    removed_but_reported_failed = reported_failed - remaining
    assert not removed_but_reported_failed, (
        f"keys reported as a contention FAILURE but were actually removed anyway "
        f"(inconsistent tag state): {removed_but_reported_failed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
