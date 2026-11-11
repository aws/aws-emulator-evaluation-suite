"""cloudformation-stack-query-group-membership."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudformation-stack-query-group-membership"
GROUP = "data-plane"
SERVICES = ["resource-groups"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
    }
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLOUDFORMATION_STACK_1_0 query resolves real stack members via ListGroupResources, and
    membership stops resolving once the group itself is deleted."""
    cfn = ctx.client("cloudformation")
    rg = ctx.client("resource-groups")

    stack_name = ctx.unique_name("sim2real-rg-cfn-")
    create = cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE)
    stack_id = create["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    topic_resource = next(r for r in resources if r["ResourceType"] == "AWS::SNS::Topic")
    topic_arn = topic_resource["PhysicalResourceId"]

    group_name = ctx.unique_name("sim2real-rg-cfngroup-")
    query = {
        "Type": "CLOUDFORMATION_STACK_1_0",
        "Query": json.dumps({"ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": stack_id}),
    }
    rg.create_group(Name=group_name, ResourceQuery=query)

    def _cleanup_group():
        # Already deleted by the check body itself is fine; anything else is a real leak signal.
        try:
            rg.delete_group(Group=group_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_group)

    def probe():
        return {i["Identifier"]["ResourceArn"] for i in rg.list_group_resources(Group=group_name)["Resources"]}

    members = _poll_until(probe, lambda arns: topic_arn in arns, timeout_s=240.0, interval_s=15.0)
    assert topic_arn in members, f"stack topic {topic_arn} never appeared as a CFN-stack-query group member"

    rg.delete_group(Group=group_name)
    code, message = _client_error(lambda: rg.list_group_resources(Group=group_name), expect="NotFoundException")
    assert code == "NotFoundException", (
        f"list_group_resources on deleted group {group_name} returned {code!r}, want NotFoundException"
    )
    assert message == "The specified group does not exist", (
        f"list_group_resources on deleted group {group_name} returned message {message!r}"
    )


def _client_error(fn, *, expect):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {expect} but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
