"""list-resources-contains-created."""
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

def _create_and_wait(cc, ctx, type_name, desired_state, client_token=None, track=True):
    """CreateResource and wait for a terminal state; track the identifier for
    cleanup on success. Returns the final ProgressEvent."""
    kwargs = {"TypeName": type_name, "DesiredState": desired_state}
    if client_token:
        kwargs["ClientToken"] = client_token
    resp = cc.create_resource(**kwargs)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier)
    return event

def _list_resources_all_identifiers(cc, type_name):
    """Walk every ListResources page (NextToken, not MaxResults -- MaxResults
    is documented "Reserved" on this operation) and return the union of
    Identifiers seen. A single page is not the whole inventory once an
    account holds more resources of this type than fit on one page."""
    identifiers = set()
    next_token = None
    while True:
        kwargs = {"TypeName": type_name}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resources(**kwargs)
        identifiers.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return identifiers

def _log_group_desired_state(name, retention_days=7):
    return json.dumps({
        "LogGroupName": name,
        "RetentionInDays": retention_days,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    })

CHECK = "list-resources-contains-created"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResources enumerates a just-created resource by identifier."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-loggroup-")
    event = _create_and_wait(cc, ctx, LOG_GROUP_TYPE, _log_group_desired_state(name))
    assert event["OperationStatus"] == "SUCCESS", f"create did not succeed: {event}"

    def probe():
        return _list_resources_all_identifiers(cc, LOG_GROUP_TYPE)

    _poll_until(probe, lambda ids: name in ids, timeout_s=120, interval_s=3)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
