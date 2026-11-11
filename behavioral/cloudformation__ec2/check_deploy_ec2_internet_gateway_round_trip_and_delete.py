"""deploy-ec2-internet-gateway-round-trip-and-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-internet-gateway-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]


def _template(tag_value: str, name_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Igw": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "sim2real", "Value": tag_value},
                        {"Key": "Name", "Value": name_value},
                    ]
                },
            }
        },
        "Outputs": {"IgwId": {"Value": {"Ref": "Igw"}}},
    })


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_stack_and_wait(cfn, stack: str) -> None:
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cfn.delete_stack(StackName=stack)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation CREATE_COMPLETE for AWS::EC2::InternetGateway produces a gateway EC2
    itself reports with the template's tags, and deleting the stack removes it:
    DescribeInternetGateways then raises InvalidInternetGatewayID.NotFound with its exact message.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-internetgateway.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2igw-")
    name_value = ctx.unique_name("sim2real-ec2igw-name-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(CHECK, name_value))
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_stack_and_wait(cfn, stack))())

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    igw_id = outputs["IgwId"]
    assert igw_id.startswith("igw-"), f"IgwId output {igw_id!r} does not look like an IGW id"

    before = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"]
    assert before, f"DescribeInternetGateways({igw_id!r}) returned no gateways"
    got_tags = {t["Key"]: t["Value"] for t in before[0]["Tags"]}
    assert got_tags.get("sim2real") == CHECK, (
        f"expected the sim2real tag to carry {CHECK!r}, EC2 reports tags {got_tags!r}"
    )
    assert got_tags.get("Name") == name_value, (
        f"expected the Name tag to carry {name_value!r}, EC2 reports tags {got_tags!r}"
    )
    assert before[0]["Attachments"] == [], (
        f"a freshly created, unattached internet gateway reports attachments "
        f"{before[0]['Attachments']!r}, expected none"
    )
    # AWS::EC2::InternetGateway declares no Fn::GetAtt attributes (Ref is the only return
    # value), so there is nothing beyond Tags and the id itself to round-trip here.

    _delete_stack_and_wait(cfn, stack)
    final_status = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final_status == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after delete, DescribeStacks({stack!r}) raised {final_status!r}, expected the "
        f"name not to resolve"
    )

    code, message = _error(lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]))
    assert code == "InvalidInternetGatewayID.NotFound", (
        f"expected InvalidInternetGatewayID.NotFound reading the deleted gateway, got {code!r}: "
        f"{message!r}"
    )
    want_message = f"The internetGateway ID '{igw_id}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
