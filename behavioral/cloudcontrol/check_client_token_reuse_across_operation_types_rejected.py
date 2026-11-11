"""client-token-reuse-across-operation-types-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-reuse-across-operation-types-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]

SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
VALUE = "must-survive-the-conflicting-delete"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ClientToken is scoped to a request: reusing a create's token on a delete is
    ClientTokenConflictException and the parameter survives; a fresh token then deletes it.
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-ccxop-")
    create_token = str(uuid.uuid4())

    created = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps(
            {"Name": name, "Type": "String", "Value": VALUE, "Tags": {"sim2real": CHECK}}
        ),
        ClientToken=create_token,
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"create did not succeed: status {create_event['OperationStatus']!r}, ErrorCode "
        f"{create_event.get('ErrorCode')!r}, StatusMessage "
        f"{create_event.get('StatusMessage')!r}"
    )
    before = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert before["Value"] == VALUE, (
        f"SSM holds Value {before['Value']!r} after the create, expected {VALUE!r}"
    )

    conflict_code, conflict_message = _client_error(
        lambda: cc.delete_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name, ClientToken=create_token
        )
    )
    assert conflict_code == "ClientTokenConflictException", (
        f"DeleteResource under the ClientToken already consumed by the create was answered "
        f"{conflict_code!r}, expected ClientTokenConflictException; a token identifies a REQUEST, "
        f"so a delete presenting a create's token is 'another resource request' and must be "
        f"refused rather than executed"
    )
    expected_conflict = (
        f"ClientToken {create_token} is already associated with an existing operation with "
        f"RequestToken {create_event['RequestToken']}"
    )
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    survivor = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert survivor["Value"] == VALUE, (
        f"SSM reports Value {survivor['Value']!r} after the refused delete, expected the "
        f"untouched {VALUE!r}"
    )
    assert survivor["Version"] == 1, (
        f"SSM reports Version {survivor['Version']!r} after the refused delete, expected the "
        f"untouched 1"
    )
    matched = _describe_names(ssm, name)
    assert matched == [name], (
        f"ssm:DescribeParameters reports {matched!r} for {name!r} after the refused delete; the "
        f"parameter must still be there"
    )

    removed = cc.delete_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=name, ClientToken=str(uuid.uuid4())
    )
    delete_event = _wait_terminal(cc, removed["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", (
        f"the identical DeleteResource under a FRESH ClientToken terminated "
        f"{delete_event['OperationStatus']!r} with ErrorCode "
        f"{delete_event.get('ErrorCode')!r}, expected SUCCESS; if this fails, the refusal above "
        f"was not about the token"
    )
    gone_code, gone_message = _client_error(lambda: ssm.get_parameter(Name=name))
    assert gone_code == "ParameterNotFound", (
        f"SSM answers {gone_code!r} for {name!r} after the fresh-token delete reported SUCCESS, "
        f"expected ParameterNotFound"
    )
    assert gone_message == "", f"expected SSM's empty ParameterNotFound message, got {gone_message!r}"
    still_matched = _describe_names(ssm, name)
    assert still_matched == [], (
        f"ssm:DescribeParameters still reports {still_matched!r} after the delete succeeded"
    )




def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
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


def _client_error(fn):
    """The AWS (error code, message) raised by fn(); raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _describe_names(ssm, name):
    """Names DescribeParameters returns for an exact name, a read path besides GetParameter."""
    found = []
    paginator = ssm.get_paginator("describe_parameters")
    for page in paginator.paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found.extend(p["Name"] for p in page["Parameters"])
    return found


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
