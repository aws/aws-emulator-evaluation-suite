"""deploy-vpc-endpoint-cfn-becomes-available."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-vpc-endpoint-cfn-becomes-available"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed VpcEndpoint becomes ACTIVE and resolves via BatchGet."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    aoss = ctx.client("opensearchserverless")
    tag_value = ctx.unique_name("sim2real-cfnvpce")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16", TagSpecifications=[_tag_spec("vpc", tag_value)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    # An interface VpcEndpoint enables private DNS, which AWS rejects unless the VPC already
    # has both attributes on (real AWS: "Enabling private DNS requires both enableDnsSupport
    # and enableDnsHostnames VPC attributes set to true" -- a freshly created non-default VPC
    # has enableDnsHostnames=False).
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.92.0.0/24", TagSpecifications=[_tag_spec("subnet", tag_value)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    stack_name = ctx.unique_name("sim2real-aoss-vpce-stack-")
    endpoint_name = _short_name(ctx, "sim2real-cfnvpce")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Endpoint": {
                    "Type": "AWS::OpenSearchServerless::VpcEndpoint",
                    "Properties": {
                        "Name": endpoint_name,
                        "VpcId": vpc_id,
                        "SubnetIds": [subnet_id],
                    },
                }
            },
            "Outputs": {"EndpointId": {"Value": {"Ref": "Endpoint"}}},
        }
    )

    stack_id = _deploy_cfn(ctx, cfn, stack_name, template, timeout_s=1200)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }
    endpoint_id = outputs["EndpointId"]

    details = aoss.batch_get_vpc_endpoint(ids=[endpoint_id])["vpcEndpointDetails"]
    assert len(details) == 1
    assert details[0]["status"] == "ACTIVE"
    assert details[0]["name"] == endpoint_name
    assert details[0]["vpcId"] == vpc_id


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "behavioral"}],
    }


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _deploy_cfn(ctx: Any, cfn: Any, stack_name: str, template_body: str, *, timeout_s: float) -> str:

    def _cleanup() -> None:
        try:
            cfn.delete_stack(StackName=stack_id)
            _poll_until(
                lambda: _stack_status(cfn, stack_id),
                lambda s: s in (None, "DELETE_COMPLETE"),
                timeout_s=timeout_s,
                interval_s=15,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=template_body, OnFailure="DELETE")[
        "StackId"
    ]
    ctx.on_cleanup(_cleanup)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE"),
        timeout_s=timeout_s,
        interval_s=15,
    )
    assert status == "CREATE_COMPLETE", f"stack ended in {status}: {_failure_reasons(cfn, stack_id)}"
    return stack_id


def _failure_reasons(cfn: Any, stack_id: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    except Exception as exc:
        return f"<could not fetch stack events: {exc}>"
    reasons = [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', e['ResourceStatus'])}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]
    return "; ".join(reasons) or "<no FAILED events found>"


def _stack_status(cfn: Any, stack_id: str) -> str | None:
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except Exception:
        return None


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
