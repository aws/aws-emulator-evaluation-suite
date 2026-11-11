"""cloudcontrol-concurrent-patches-native-version-count-equals-successes."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-concurrent-patches-native-version-count-equals-successes"
GROUP = 'concurrency'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
FANOUT = 6


def _poll_until(probe, predicate, *, timeout_s=150, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=150, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Six concurrent UpdateResource patches of one SSM parameter are each accepted or refused with
    ConcurrentOperationException, at least one succeeds, and SSM's gap-free version history ends at
    1 + successes with a submitted value."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-ccrace-")

    created = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": name, "Type": "String", "Value": "v0", "Tags": {"sim2real": CHECK},
        }),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event!r}"

    markers = [f"marker-{i}" for i in range(FANOUT)]

    def _submit(marker):
        try:
            resp = cc.update_resource(
                TypeName=SSM_PARAM_TYPE, Identifier=name,
                PatchDocument=json.dumps([{"op": "replace", "path": "/Value", "value": marker}]),
            )
            return ("accepted", marker, resp["ProgressEvent"]["RequestToken"])
        except ClientError as exc:
            return ("refused", marker, exc.response["Error"]["Code"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=FANOUT) as pool:
        submitted = list(pool.map(_submit, markers))

    successes, rejected_codes, failures = [], [], []
    for kind, marker, payload in submitted:
        if kind == "refused":
            rejected_codes.append(payload)
            continue
        event = _wait_terminal(cc, payload)
        if event["OperationStatus"] == "SUCCESS":
            successes.append(marker)
        else:
            failures.append((marker, event.get("ErrorCode"), event.get("StatusMessage")))

    assert len(successes) + len(rejected_codes) + len(failures) == FANOUT, (
        f"accounted for {len(successes) + len(rejected_codes) + len(failures)} of {FANOUT} "
        f"submissions: {submitted!r}"
    )
    assert len(successes) >= 1, (
        f"every concurrent update was rejected -- refusals {rejected_codes!r}, "
        f"terminal failures {failures!r}"
    )
    assert set(rejected_codes) - {"ConcurrentOperationException"} == set(), (
        f"a concurrent update was refused with an unexpected code: {rejected_codes!r}"
    )

    history = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        history.extend({"Version": h["Version"], "Value": h["Value"]} for h in page["Parameters"])
    history.sort(key=lambda h: h["Version"])
    assert history[-1]["Version"] == 1 + len(successes), (
        f"SSM is at version {history[-1]['Version']!r} after {len(successes)} successful updates "
        f"({successes!r}); a write was lost or invented"
    )
    assert [h["Version"] for h in history] == list(range(1, len(history) + 1)), (
        f"SSM version history has a gap: {[h['Version'] for h in history]!r}"
    )
    assert history[-1]["Value"] in markers, (
        f"the surviving native value {history[-1]['Value']!r} was never submitted; submitted "
        f"{markers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
