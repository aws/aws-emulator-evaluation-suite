"""concurrent-update-same-identifier-race."""
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

def _create_and_wait(cc, ctx, teardown, type_name, desired_state, client_token=None):
    """CreateResource, register its cleanup, and wait for a terminal state. Returns the final
    ProgressEvent."""
    kwargs = {"TypeName": type_name, "DesiredState": desired_state}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.create_resource(**kwargs)
    token = resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, type_name, token, teardown))
    return _wait_terminal(cc, token)


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)

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

CHECK = "concurrent-update-same-identifier-race"
GROUP = 'concurrency'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent UpdateResource calls on one SSM parameter each end SUCCESS or fail with
    ConcurrentOperationException "Concurrent operation found for resource <name>", at least one succeeds, and the
    final GetResource Value is one of the submitted values."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    teardown = _Teardown()
    create_event = _create_and_wait(cc, ctx, teardown, SSM_PARAM_TYPE, _ssm_desired_state(name, value="initial"))
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event!r}"

    n = 5
    candidate_values = [f"racer-value-{i}" for i in range(n)]

    def attempt(v):
        patch = json.dumps([{"op": "replace", "path": "/Value", "value": v}])
        resp = cc.update_resource(TypeName=SSM_PARAM_TYPE, Identifier=name, PatchDocument=patch)
        token = resp["ProgressEvent"]["RequestToken"]
        return _wait_terminal(cc, token)

    results = _run_concurrent([lambda v=v: attempt(v) for v in candidate_values])

    def outcome_code(r):
        if isinstance(r, BaseException):
            return getattr(r, "response", {}).get("Error", {}).get("Code")
        if r.get("OperationStatus") == "SUCCESS":
            return "SUCCESS"
        return r.get("ErrorCode")

    codes = [outcome_code(r) for r in results]
    successes = [c for c in codes if c == "SUCCESS"]
    losers = [c for c in codes if c != "SUCCESS"]

    assert len(successes) >= 1, f"at least one concurrent update should succeed: {results}"
    for c in losers:
        assert c == "ConcurrentOperationException", (
            f"losing racer got unexpected outcome code: {c!r} (all outcomes: {codes!r})"
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
    props = json.loads(resp["ResourceDescription"]["Properties"])
    assert props.get("Value") in candidate_values, (
        f"final value {props.get('Value')!r} must be one of the racers' attempted values"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
