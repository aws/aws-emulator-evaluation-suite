"""concurrent-create-same-identifier-race."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus until the request reaches a terminal
    OperationStatus. Returns the final ProgressEvent dict."""
    holder = {}

    def probe():
        resp = cc.get_resource_request_status(RequestToken=request_token)
        holder["event"] = resp["ProgressEvent"]
        return holder["event"]

    _poll_until(
        probe,
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return holder["event"]

def _delete_quiet(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value, "Tags": {"sim2real": CHECK}})

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results (or captured exceptions) in submission order."""
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 - captured for the caller to assert on
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

CHECK = "concurrent-create-same-identifier-race"
GROUP = 'concurrency'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Firing N concurrent CreateResource calls for the SAME identifier must serialize to exactly one caller receiving a successful CREATE while the rest are rejected (ConcurrentOperationException while in flight, or AlreadyExistsException once the winner has landed) -- never two resources silently coexisting or duplicate winners."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    n = 5

    def attempt(i):
        resp = cc.create_resource(
            TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name, value=f"racer-{i}")
        )
        token = resp["ProgressEvent"]["RequestToken"]
        return _wait_terminal(cc, token)

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(n)])
    _track(cc, ctx, SSM_PARAM_TYPE, name)

    def outcome_code(r):
        if isinstance(r, BaseException):
            return getattr(r, "response", {}).get("Error", {}).get("Code")
        if r.get("OperationStatus") == "SUCCESS":
            return "SUCCESS"
        return r.get("ErrorCode")

    codes = [outcome_code(r) for r in results]
    successes = [c for c in codes if c == "SUCCESS"]
    losers = [c for c in codes if c != "SUCCESS"]

    assert len(successes) == 1, f"expected exactly one winning create, got {len(successes)} of {codes}"
    for c in losers:
        assert c in ("AlreadyExists", "AlreadyExistsException", "ConcurrentOperationException"), (
            f"losing racer got unexpected outcome code: {c} (all: {codes})"
        )

    # The RequestToken a message may close with names the in-flight request, which no racer sees.
    for message in [
        getattr(r, "response", {}).get("Error", {}).get("Message", "")
        for r in results
        if isinstance(r, BaseException) and outcome_code(r) == "ConcurrentOperationException"
    ]:
        assert message.split(" with RequestToken ", 1)[0] == f"Concurrent operation found for resource {name}", (
            f"unexpected ConcurrentOperationException message: {message!r}"
        )

    resp = _get_resource(cc, SSM_PARAM_TYPE, name)
    assert resp["ResourceDescription"]["Identifier"] == name

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
