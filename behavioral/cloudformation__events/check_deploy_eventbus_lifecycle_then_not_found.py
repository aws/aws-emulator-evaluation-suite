"""deploy-eventbus-lifecycle-then-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventbus-lifecycle-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Events::EventBus is readable through EventBridge's own
    DescribeEventBus with the template's name and the stack's Fn::GetAtt Arn/Name outputs, and
    deleting the stack removes it: DescribeEventBus then raises ResourceNotFoundException naming it.
    """
    cfn = ctx.client("cloudformation")
    ev = ctx.client("events")
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    stack_name = ctx.unique_name("sim2real-behav-bus-stack-")
    template = json.dumps({
        "Resources": {
            "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": bus_name}},
        },
        "Outputs": {
            "BusRef": {"Value": {"Ref": "Bus"}},
            "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}},
            "BusName": {"Value": {"Fn::GetAtt": ["Bus", "Name"]}},
        },
    })

    cfn.create_stack(StackName=stack_name, TemplateBody=template,
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    assert outputs["BusRef"] == bus_name, f"Ref should be the bus name, got {outputs['BusRef']!r}"
    assert outputs["BusName"] == bus_name, (
        f"GetAtt Name should be the bus name, got {outputs['BusName']!r}"
    )

    described = ev.describe_event_bus(Name=bus_name)
    assert outputs["BusArn"] == described["Arn"], (
        f"GetAtt Arn {outputs['BusArn']!r} must match EventBridge's own Arn {described['Arn']!r}"
    )
    assert described["Name"] == bus_name, (
        f"DescribeEventBus Name should be {bus_name!r}, got {described['Name']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    code, message = _error(lambda: ev.describe_event_bus(Name=bus_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after stack delete, got {code!r}"
    )
    assert message == f"Event bus {bus_name} does not exist.", (
        f"unexpected not-found message: {message!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
