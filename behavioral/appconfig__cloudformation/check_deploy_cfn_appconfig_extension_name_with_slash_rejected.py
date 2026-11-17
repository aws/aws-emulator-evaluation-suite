"""deploy-cfn-appconfig-extension-name-with-slash-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-extension-name-with-slash-rejected"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)

_URI = {"Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:event-bus/default"}


def _extension_template(ext_name: str) -> str:
    """A lone AWS::AppConfig::Extension with one ON_DEPLOYMENT_START action to the default bus."""
    resources = {
        "Ext": {
            "Type": "AWS::AppConfig::Extension",
            "Properties": {
                "Name": ext_name,
                "Actions": {"ON_DEPLOYMENT_START": [{"Name": "notify-default-bus", "Uri": _URI}]},
            },
        },
    }
    outputs = {"ExtId": {"Value": {"Ref": "Ext"}}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _poll_terminal(cf, stack_id: str, deadline_s: float = 240.0) -> str:
    deadline = time.monotonic() + deadline_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} still {status!r} after {deadline_s:.0f}s")
        time.sleep(3)


def _create_failed_reason(cf, stack_id: str, logical_id: str) -> str:
    reasons = [
        e.get("ResourceStatusReason", "")
        for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id!r}, got {reasons!r}"
    return reasons[0]


def _not_found(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _destroy(cf, stack_id: str) -> None:
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _poll_terminal(cf, stack_id, deadline_s=240.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::AppConfig::Extension whose Name holds a '/' fails CloudFormation creation with
    AppConfig's exact pattern error and mints nothing, while the same template with a
    slash-free Name deploys."""
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    ok_stack = ctx.unique_name("sim2real-acfgext2-okstack-")
    ok_name = ctx.unique_name("sim2real-acfgext2-ok-")
    bad_stack = ctx.unique_name("sim2real-acfgext2-badstack-")
    bad_name = ctx.unique_name("sim2real-acfgext2-bad-") + "/child"

    # Positive control: the identical shape with a slash-free Name, through CloudFormation.
    ok_stack_id = cf.create_stack(
        StackName=ok_stack, TemplateBody=_extension_template(ok_name),
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy(cf, ok_stack_id))
    status = _poll_terminal(cf, ok_stack_id)
    assert status == "CREATE_COMPLETE", f"positive control: expected CREATE_COMPLETE, got {status!r}"
    ok_ext_id = cf.describe_stacks(StackName=ok_stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    ok_ext = appconfig.get_extension(ExtensionIdentifier=ok_ext_id)
    assert ok_ext["Name"] == ok_name, f"positive control: Name {ok_ext['Name']!r} != {ok_name!r}"

    # The one thing broken: a '/' in the Name, which AppConfig's pattern forbids.
    bad_stack_id = cf.create_stack(
        StackName=bad_stack, TemplateBody=_extension_template(bad_name), DisableRollback=True,
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy(cf, bad_stack_id))
    status = _poll_terminal(cf, bad_stack_id)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"

    reason = _create_failed_reason(cf, bad_stack_id, "Ext")
    match = _HANDLER_REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: ^[^\/#:\n]{1,64}$",
        "AppConfig", "400", "InvalidRequest",
    )
    assert got == want, f"CREATE_FAILED reason: expected {want!r}, got {got!r}"

    names = set()
    for page in appconfig.get_paginator("list_extensions").paginate():
        names.update(item["Name"] for item in page["Items"])
    assert bad_name not in names, f"the rejected extension {bad_name!r} was minted into the account"

    for stack_id in (bad_stack_id, ok_stack_id):
        cf.delete_stack(StackName=stack_id)
        status = _poll_terminal(cf, stack_id, deadline_s=240.0)
        assert status == "DELETE_COMPLETE", f"delete of {stack_id!r} ended {status!r}"

    got_gone = _not_found(lambda: appconfig.get_extension(ExtensionIdentifier=ok_ext_id))
    want_gone = (
        "ResourceNotFoundException",
        f"Extension could not be found for account {ctx.account}.",
    )
    assert got_gone == want_gone, f"GetExtension after the control stack's delete: {got_gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
