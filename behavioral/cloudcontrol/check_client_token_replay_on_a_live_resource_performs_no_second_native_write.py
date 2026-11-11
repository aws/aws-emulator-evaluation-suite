"""client-token-replay-on-a-live-resource-performs-no-second-native-write."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-replay-on-a-live-resource-performs-no-second-native-write"
GROUP = "native-truth"
SERVICES = ["cloudcontrol"]

SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
VALUE = "tokened-once"


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A ClientToken replay of CreateResource against a LIVE resource writes SSM exactly once (the
    native parameter Version and history stay at 1), while a create of the same name under a fresh
    token is refused with AlreadyExists, so a target that swallows every duplicate cannot pass.
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-cclive-")
    token = str(uuid.uuid4())
    desired_state = json.dumps(
        {"Name": name, "Type": "String", "Value": VALUE, "Tags": {"sim2real": CHECK}}
    )

    first = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=token
    )
    # Registered before the first assertion: a FAILED terminal event can still have written the
    # parameter, and the only reapable handle is the SSM name.
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    original = _wait_terminal(cc, first["ProgressEvent"]["RequestToken"])
    assert original["OperationStatus"] == "SUCCESS", (
        f"create did not succeed: status {original['OperationStatus']!r}, ErrorCode "
        f"{original.get('ErrorCode')!r}, StatusMessage {original.get('StatusMessage')!r}"
    )

    # The baseline at the destination, established from SSM's own report (no literal version
    # number is pinned as a quota -- Version 1 is what a single write produces, by SSM's
    # documented definition of the counter).
    baseline_version = _version(ssm, name)
    assert baseline_version == 1, (
        f"SSM reports Version {baseline_version!r} after one CreateResource; a single write must "
        f"leave the parameter at version 1"
    )
    baseline_history = _history(ssm, name)
    assert baseline_history == [(1, VALUE)], (
        f"SSM parameter history is {baseline_history!r} after one CreateResource, expected "
        f"[(1, {VALUE!r})]"
    )

    # ---- the replay: a cached receipt, and NOTHING at the destination --------------------------
    for attempt in (1, 2):
        replay = cc.create_resource(
            TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=token
        )["ProgressEvent"]
        assert replay["RequestToken"] == original["RequestToken"], (
            f"replay {attempt} minted RequestToken {replay['RequestToken']!r} instead of "
            f"returning the original {original['RequestToken']!r}; a new token means the target "
            f"re-executed rather than replayed"
        )
        assert str(replay["EventTime"]) == str(original["EventTime"]), (
            f"replay {attempt} reports EventTime {replay['EventTime']!r}, the original was "
            f"{original['EventTime']!r}; a cached receipt must be verbatim"
        )
        assert replay["OperationStatus"] == "SUCCESS", (
            f"replay {attempt} reports OperationStatus {replay['OperationStatus']!r}, the "
            f"original CREATE was SUCCESS"
        )

        version_now = _version(ssm, name)
        assert version_now == 1, (
            f"after replay {attempt} SSM reports Version {version_now!r}, expected 1; a "
            f"ClientToken replay must not perform a second native write, and the write counter "
            f"is the only place that shows it"
        )
        history_now = _history(ssm, name)
        assert history_now == [(1, VALUE)], (
            f"after replay {attempt} SSM parameter history is {history_now!r}, expected exactly "
            f"one entry [(1, {VALUE!r})]"
        )

    # ---- the discriminator: the store IS real, so a fresh token on the same name is refused ----
    fresh_code, fresh_message = _normalized_failure(
        cc,
        lambda: cc.create_resource(
            TypeName=SSM_PARAM_TYPE, DesiredState=desired_state, ClientToken=str(uuid.uuid4())
        ),
    )
    assert fresh_code == "AlreadyExists", (
        f"a create for the existing name {name!r} under a FRESH ClientToken was refused with "
        f"{fresh_code!r}, expected the handler code AlreadyExists; without this leg 'the replay "
        f"wrote nothing' cannot be told apart from 'this target swallows every duplicate create'"
    )
    expected_fresh = f"Resource of type '{SSM_PARAM_TYPE}' with identifier '{name}' already exists."
    assert fresh_message == expected_fresh, (
        f"expected message {expected_fresh!r}, got {fresh_message!r}"
    )
    post_refusal_version = _version(ssm, name)
    assert post_refusal_version == 1, (
        f"the refused fresh-token create left SSM at Version {post_refusal_version!r}, expected 1"
    )

    # ---- positive control: the wiring still creates, under a fresh token and a fresh name ------
    control_name = ctx.unique_name("sim2real-behav-ccctl-")
    control = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps(
            {
                "Name": control_name,
                "Type": "String",
                "Value": "control-ok",
                "Tags": {"sim2real": CHECK},
            }
        ),
        ClientToken=str(uuid.uuid4()),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    control_event = _wait_terminal(cc, control["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control create failed: {control_event!r}"
    )
    assert control_event["RequestToken"] != original["RequestToken"], (
        f"the fresh-token create reused RequestToken {control_event['RequestToken']!r}"
    )
    assert ssm.get_parameter(Name=control_name)["Parameter"]["Value"] == "control-ok", (
        f"positive control parameter {control_name!r} is not readable from SSM with the value "
        f"the desired state asked for"
    )


# ===== helpers =====

HANDLER_ERROR_TO_EXCEPTION = {
    "AlreadyExistsException": "AlreadyExists",
    "ResourceNotFoundException": "NotFound",
    "NotUpdatableException": "NotUpdatable",
    "InvalidRequestException": "InvalidRequest",
}


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _normalized_failure(cc, call):
    """The HANDLER (error code, message) for a call expected to be refused, whether it arrives
    synchronously (as an exception name, normalised back to the handler taxonomy) or as a terminal
    FAILED ProgressEvent's ErrorCode and StatusMessage. RAISES if the call is ACCEPTED -- a falsy sentinel there would let
    an over-permissive target pass acceptance off as a code mismatch."""
    try:
        resp = call()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        return HANDLER_ERROR_TO_EXCEPTION.get(code, code), exc.response["Error"]["Message"]
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    status = event["OperationStatus"]
    if status != "FAILED":
        raise AssertionError(
            f"the create was expected to be refused but reached {status!r}: {event!r}"
        )
    return event.get("ErrorCode"), event.get("StatusMessage")


def _version(ssm, name):
    """SSM's own write counter for the parameter -- the side-channel no Cloud Control exchange
    can carry."""
    return ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Version"]


def _history(ssm, name):
    """Every (Version, Value) SSM retains for the parameter, in submission order."""
    entries = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        entries.extend((h["Version"], h["Value"]) for h in page["Parameters"])
    return entries


def _delete_parameter_quiet(ssm, name):
    """Teardown, scoped to the parameters this check created."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
