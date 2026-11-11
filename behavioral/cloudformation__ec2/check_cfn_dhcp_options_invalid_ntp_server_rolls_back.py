"""cfn-dhcp-options-invalid-ntp-server-rolls-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-dhcp-options-invalid-ntp-server-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_RUN_TAG = "sim2real-run"
_BAD_NTP = "not-an-ip-address"
_GOOD_NTP = "169.254.169.123"

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(ntp_server: str, run_token: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "D": {
                    "Type": "AWS::EC2::DHCPOptions",
                    "Properties": {
                        "NtpServers": [ntp_server],
                        "Tags": [
                            {"Key": "sim2real", "Value": CHECK},
                            {"Key": _RUN_TAG, "Value": run_token},
                        ],
                    },
                }
            },
        }
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::EC2::DHCPOptions with a non-IP NtpServers entry fails with EC2's own error and no
    DHCP options set carrying this run's tag exists at EC2; the same template with an IP deploys."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    run_token = ctx.unique_name("sim2real-behav-dhcprun-")
    good_stack = ctx.unique_name("sim2real-behav-cfn-dhcp-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-cfn-dhcp-bad-")

    # Positive control: the identical template with an IP address, through CloudFormation.
    _create(ctx, cfn, good_stack, _template(_GOOD_NTP, run_token))
    status = _poll_until_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_id = cfn.describe_stack_resource(StackName=good_stack, LogicalResourceId="D")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    described = ec2.describe_dhcp_options(DhcpOptionsIds=[good_id])["DhcpOptions"]
    configs = {c["Key"]: [v["Value"] for v in c["Values"]] for c in described[0]["DhcpConfigurations"]}
    assert configs.get("ntp-servers") == [_GOOD_NTP], (
        f"control DHCP options {good_id!r}: expected ntp-servers [{_GOOD_NTP!r}], got {configs!r}"
    )

    # The one thing broken: an NtpServers entry that is not an IP address.
    _create(ctx, cfn, bad_stack, _template(_BAD_NTP, run_token))
    status = _poll_until_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    reason = _failed_reason(cfn, bad_stack, "D")
    match = _REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        f"Value ({_BAD_NTP}) for parameter value is invalid. Invalid DHCP option value.",
        "Ec2",
        "400",
        "GeneralServiceException",
    )
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    # Effect absent through EC2 itself: only the control's set carries this run's tag.
    tagged = _tagged_dhcp_options(ec2, run_token)
    assert tagged == [good_id], (
        f"expected only the control DHCP options {good_id!r} to carry this run's tag, got {tagged!r}"
    )

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cfn, stack_name)
        got = _error(lambda stack_name=stack_name: cfn.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the delete of {stack_name}: {got!r}"
        )
    got = _error(lambda: ec2.describe_dhcp_options(DhcpOptionsIds=[good_id]))
    assert got == ("InvalidDhcpOptionID.NotFound", f"The dhcpOption ID '{good_id}' does not exist"), (
        f"the control DHCP options after its stack delete: {got!r}"
    )


def _tagged_dhcp_options(ec2, run_token: str) -> list[str]:
    """Ids of every DHCP options set tagged with this run's token."""
    found = []
    for page in ec2.get_paginator("describe_dhcp_options").paginate(
        Filters=[{"Name": f"tag:{_RUN_TAG}", "Values": [run_token]}]
    ):
        found.extend(d["DhcpOptionsId"] for d in page["DhcpOptions"])
    return sorted(found)


def _create(ctx, cfn, stack_name: str, body: str) -> None:
    """CreateStack with its delete registered at once."""
    cfn.create_stack(
        StackName=stack_name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float = 180.0) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}")


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event."""
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
