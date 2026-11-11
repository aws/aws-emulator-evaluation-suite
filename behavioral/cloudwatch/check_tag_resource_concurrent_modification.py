"""tag-resource-concurrent-modification."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-modification"
GROUP = 'concurrency'
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
    """Concurrent TagResource calls setting one key of one dashboard to different values fail only
    with ConcurrentModificationException/ConflictException, at least one succeeds, and the key ends
    with exactly one value, that of a writer that reported success."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-tagcc-")
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_dashboard_body("tag-race"))
    ctx.on_cleanup(lambda _n=dash_name: cw.delete_dashboards(DashboardNames=[_n]))
    dash_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dash_name}"

    n = 10

    def tag(i: int):
        return cw.tag_resource(ResourceARN=dash_arn, Tags=[{"Key": "probe", "Value": f"v{i}"}])

    results = _run_concurrent([lambda i=i: tag(i) for i in range(n)], timeout_s=60)

    codes = _concurrent_error_codes(results)
    bad_codes = [c for c in codes if c not in _NON_CONCURRENT_ERROR_CODES]
    assert not bad_codes, f"unexpected error code(s) from concurrent TagResource writers: {bad_codes}"

    successes = sum(1 for r in results if not isinstance(r, BaseException))
    assert successes >= 1, f"at least one concurrent TagResource writer must win; codes={codes}"
    winning_indices = {i for i, r in enumerate(results) if not isinstance(r, BaseException)}

    tags = cw.list_tags_for_resource(ResourceARN=dash_arn).get("Tags", [])
    probe_values = [t["Value"] for t in tags if t["Key"] == "probe"]
    assert len(probe_values) == 1, (
        f"the 'probe' tag must hold exactly ONE value after the race, not a corrupted/"
        f"duplicated set, got {probe_values}"
    )
    winning_idx = int(probe_values[0][1:])
    assert winning_idx in winning_indices, (
        f"final tag value (index {winning_idx}) must correspond to a writer that actually "
        f"reported success ({winning_indices}), got codes={codes}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
