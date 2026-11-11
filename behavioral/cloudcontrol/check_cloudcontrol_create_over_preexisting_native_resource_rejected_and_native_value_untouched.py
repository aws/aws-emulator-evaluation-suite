"""cloudcontrol-create-over-preexisting-native-resource-rejected-and-native-value-untouched."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-create-over-preexisting-native-resource-rejected-and-native-value-untouched"
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
    """CreateResource over a natively created SSM parameter fails AlreadyExists, value untouched.

    After the native parameter is deleted the same create succeeds; a fresh name is a control.
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")

    # Written directly with SSM, so Cloud Control has never seen this parameter.
    seeded = ctx.unique_name("sim2real-behav-ccseed-")
    ssm.put_parameter(
        Name=seeded, Value="native-original", Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, seeded))

    conflicting = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({"Name": seeded, "Type": "String", "Value": "via-cloudcontrol"}),
    )
    terminal = _wait_terminal(cc, conflicting["ProgressEvent"]["RequestToken"])
    assert terminal["OperationStatus"] == "FAILED", (
        f"CreateResource over a pre-existing native parameter reached {terminal!r}"
    )
    assert terminal["ErrorCode"] == "AlreadyExists", (
        f"the refusal carried ErrorCode {terminal.get('ErrorCode')!r}, expected 'AlreadyExists'"
    )
    expected = f"Resource of type '{SSM_PARAM_TYPE}' with identifier '{seeded}' already exists."
    assert terminal.get("StatusMessage") == expected, (
        f"expected StatusMessage {expected!r}, got {terminal.get('StatusMessage')!r}"
    )

    survivor = ssm.get_parameter(Name=seeded)["Parameter"]
    assert survivor["Value"] == "native-original", (
        f"Cloud Control overwrote a pre-existing native parameter: SSM now holds "
        f"{survivor['Value']!r}"
    )
    assert survivor["Version"] == 1, (
        f"SSM reports Version {survivor['Version']!r}; the version advanced, so a write happened "
        "despite the refusal"
    )

    # Replaying the refused create after removing the collision pins the refusal to it.
    ssm.delete_parameter(Name=seeded)
    try:
        ssm.get_parameter(Name=seeded)
        raise AssertionError(f"deleted native parameter {seeded!r} is still readable from SSM")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ParameterNotFound", (
            f"deleted native parameter read back error code "
            f"{e.response['Error']['Code']!r}, expected 'ParameterNotFound'"
        )
        assert e.response["Error"]["Message"] == "", (
            f"expected SSM's empty ParameterNotFound message, got {e.response['Error']['Message']!r}"
        )

    retried = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({"Name": seeded, "Type": "String", "Value": "via-cloudcontrol"}),
    )
    retried_terminal = _wait_terminal(cc, retried["ProgressEvent"]["RequestToken"])
    assert retried_terminal["OperationStatus"] == "SUCCESS", (
        f"after removing the blocking native parameter, the identical create call must succeed, "
        f"got {retried_terminal!r}"
    )
    assert ssm.get_parameter(Name=seeded)["Parameter"]["Value"] == "via-cloudcontrol", (
        "the identifier freed by deleting the native parameter was recreated via CloudControl but "
        "does not hold the value that create supplied"
    )

    control_name = ctx.unique_name("sim2real-behav-ccctl-")
    control = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": control_name, "Type": "String", "Value": "control-ok",
            "Tags": {"sim2real": CHECK},
        }),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    control_event = _wait_terminal(cc, control["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control failed: {control_event!r}"
    )
    assert ssm.get_parameter(Name=control_name)["Parameter"]["Value"] == "control-ok", (
        f"positive control parameter {control_name!r} is not readable from SSM with the value it "
        "was created with"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
