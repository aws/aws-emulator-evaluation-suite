"""cloudcontrol-client-token-replay-after-delete-returns-cached-event-not-resurrected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-client-token-replay-after-delete-returns-cached-event-not-resurrected"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=120, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _client_error(fn):
    """The AWS (error code, message) raised by fn(). Raises if the call unexpectedly SUCCEEDS -- returning a
    falsy sentinel there would turn the strongest possible signal into a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """After DeleteResource, a CreateResource replay with the same ClientToken returns the original
    ProgressEvent (same RequestToken, EventTime and SUCCESS) and SSM still holds no parameter; the same
    DesiredState under a fresh ClientToken creates it."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-cctok-")
    token = str(uuid.uuid4())
    desired_state = json.dumps({
        "Name": name, "Type": "String", "Value": "tokened", "Tags": {"sim2real": CHECK},
    })

    first = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=token,
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    original = _wait_terminal(cc, first["ProgressEvent"]["RequestToken"])
    assert original["OperationStatus"] == "SUCCESS", f"create did not succeed: {original!r}"
    assert ssm.get_parameter(Name=name)["Parameter"]["Value"] == "tokened", (
        f"the parameter {name!r} is not readable from SSM after a successful CreateResource"
    )

    removed = cc.delete_resource(TypeName=SSM_PARAM_TYPE, Identifier=name)
    delete_event = _wait_terminal(cc, removed["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not succeed: {delete_event!r}"
    deleted_code, deleted_message = _client_error(lambda: ssm.get_parameter(Name=name))
    assert deleted_code == "ParameterNotFound", (
        f"SSM still answers {deleted_code!r} for {name!r} after DeleteResource succeeded"
    )
    assert deleted_message == "", (
        f"expected SSM's empty ParameterNotFound message, got {deleted_message!r}"
    )

    replay = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=token,
    )["ProgressEvent"]
    assert replay["RequestToken"] == original["RequestToken"], (
        f"the replay minted RequestToken {replay['RequestToken']!r} instead of returning the "
        f"original {original['RequestToken']!r}, so it re-executed rather than replaying"
    )
    assert replay["EventTime"] == original["EventTime"], (
        f"the replay reports EventTime {replay['EventTime']!r}, the original was "
        f"{original['EventTime']!r}"
    )
    assert replay["OperationStatus"] == "SUCCESS", (
        f"the replayed receipt reports {replay['OperationStatus']!r}, the original CREATE was "
        "SUCCESS and a cached receipt must be unchanged by the later delete"
    )

    post_replay_code, post_replay_message = _client_error(lambda: ssm.get_parameter(Name=name))
    assert post_replay_code == "ParameterNotFound", (
        f"a ClientToken replay resurrected the parameter: SSM answered {post_replay_code!r}"
    )
    assert post_replay_message == "", (
        f"expected SSM's empty ParameterNotFound message, got {post_replay_message!r}"
    )
    matched = []
    for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]):
        matched.extend(m["Name"] for m in page["Parameters"])
    assert matched == [], f"ssm:DescribeParameters found {matched!r} after the token replay"

    control_name = ctx.unique_name("sim2real-behav-ccctl-")
    control = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": control_name, "Type": "String", "Value": "fresh-token",
            "Tags": {"sim2real": CHECK},
        }),
        ClientToken=str(uuid.uuid4()),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    control_event = _wait_terminal(cc, control["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control failed: {control_event!r}"
    )
    assert control_event["RequestToken"] != original["RequestToken"], (
        f"the fresh-token create reused RequestToken {control_event['RequestToken']!r}"
    )
    assert ssm.get_parameter(Name=control_name)["Parameter"]["Value"] == "fresh-token", (
        f"positive control parameter {control_name!r} is not readable from SSM"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
