"""cloudcontrol-update-absent-identifier-denied-and-writes-nothing-native."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-update-absent-identifier-denied-and-writes-nothing-native"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
PATCH = json.dumps([{"op": "replace", "path": "/Value", "value": "patched"}])


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
    """The botocore Error dict raised by fn(); raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """UpdateResource on a never-created identifier is the SSM handler's NotFound; nothing upserted.

    The same PatchDocument applied to an existing parameter succeeds as a control.
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")

    ghost = ctx.unique_name("sim2real-behav-ccghost-")
    pre = _client_error(lambda: ssm.get_parameter(Name=ghost))
    assert pre["Code"] == "ParameterNotFound", (
        f"the setup assumed {ghost!r} does not exist, but SSM answered {pre!r}"
    )
    assert pre["Message"] == "", (
        f"expected SSM's empty ParameterNotFound message, got {pre['Message']!r}"
    )

    err = _client_error(lambda: cc.update_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=ghost, PatchDocument=PATCH,
    ))
    assert err["Code"] == "ResourceNotFoundException", (
        f"UpdateResource against an absent identifier raised {err!r}"
    )
    # The handler's HandlerErrorCode, not Cloud Control's schema validation (ValidationException).
    expected = _handler_not_found(SSM_PARAM_TYPE, ghost, err["Message"])
    assert err["Message"] == expected, (
        f"the refusal message does not name the handler error code: {err['Message']!r}"
    )

    post = _client_error(lambda: ssm.get_parameter(Name=ghost))
    assert post["Code"] == "ParameterNotFound", (
        f"a parameter was created by a failed UpdateResource: SSM answered {post!r}"
    )
    assert post["Message"] == "", (
        f"expected SSM's empty ParameterNotFound message, got {post['Message']!r}"
    )
    # Paginated, so other parameters in the account cannot hide a match.
    matched = []
    for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [ghost]}]):
        matched.extend(m["Name"] for m in page["Parameters"])
    assert matched == [], f"ssm:DescribeParameters found {matched!r} after a refused update"

    control_name = ctx.unique_name("sim2real-behav-ccctl-")
    created = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": control_name, "Type": "String", "Value": "before",
            "Tags": {"sim2real": CHECK},
        }),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"positive control create failed: {create_event!r}"
    )
    control_patch = cc.update_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=control_name, PatchDocument=PATCH,
    )
    control_event = _wait_terminal(cc, control_patch["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control patch failed: {control_event!r}"
    )
    control_after = ssm.get_parameter(Name=control_name)["Parameter"]
    assert control_after["Value"] == "patched", (
        f"positive control SSM Value is {control_after['Value']!r}, expected 'patched'"
    )
    assert control_after["Version"] == 2, (
        f"positive control SSM Version is {control_after['Version']!r}, expected 2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
