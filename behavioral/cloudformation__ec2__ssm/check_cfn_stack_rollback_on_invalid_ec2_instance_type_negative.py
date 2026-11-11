"""cfn-stack-rollback-on-invalid-ec2-instance-type-negative."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-rollback-on-invalid-ec2-instance-type-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A stack whose EC2 instance has an invalid InstanceType reaches ROLLBACK_COMPLETE with the type
    named in the failure reason, no dependent SSM association event and no EC2 instance; a sibling
    stack differing only in InstanceType reaches CREATE_COMPLETE (positive control)."""

    def _template(instance_type: str) -> str:
        return json.dumps(
            {
                "Parameters": {
                    "ImageId": {
                        "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                        "Default": _AMI_PARAM,
                    }
                },
                "Resources": {
                    "TheInstance": {
                        "Type": "AWS::EC2::Instance",
                        "Properties": {
                            "ImageId": {"Ref": "ImageId"},
                            "InstanceType": instance_type,
                            "Tags": _xsvc_tags_kv(),
                            "SubnetId": ctx.network().subnet_ids[0],
                        },
                    },
                    "TheAssociation": {
                        "Type": "AWS::SSM::Association",
                        "Properties": {
                            "Name": "AWS-RunShellScript",
                            "Targets": [
                                {
                                    "Key": "InstanceIds",
                                    "Values": [{"Ref": "TheInstance"}],
                                }
                            ],
                            "Parameters": {"commands": ["echo sim2real"]},
                        },
                    },
                },
                "Outputs": {"InstanceId": {"Value": {"Ref": "TheInstance"}}},
            }
        )

    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    # --- broken: invalid instance type ---
    bad_name, bad_status = _deploy_expect_terminal(
        ctx, _template("sim2real.invalid-type")
    )
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {bad_status}"
    )

    events = cfn.describe_stack_events(StackName=bad_name)["StackEvents"]
    assoc_events = [e for e in events if e["LogicalResourceId"] == "TheAssociation"]
    assert assoc_events == [], (
        f"SSM association was attempted despite its EC2 dependency failing: {assoc_events}"
    )

    orphan_instances = ec2.describe_instances(
        Filters=[
            {"Name": "tag:sim2real:managed", "Values": ["true"]},
            {"Name": "tag:aws:cloudformation:stack-name", "Values": [bad_name]},
        ]
    )["Reservations"]
    assert orphan_instances == [], (
        f"an EC2 instance was created despite the invalid type: {orphan_instances}"
    )

    # The rollback must be attributable to the InstanceType we broke, not merely "something
    # failed" -- otherwise a template broken for an unrelated reason (bad image id, missing
    # capability) would score identically to this specific negative.
    instance_events = [e for e in events if e["LogicalResourceId"] == "TheInstance"]
    failed_instance_events = [
        e for e in instance_events if e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert failed_instance_events, (
        f"TheInstance never reported CREATE_FAILED; events were: {instance_events}"
    )
    reasons = " ".join(
        e.get("ResourceStatusReason", "") for e in failed_instance_events
    )
    assert "sim2real.invalid-type" in reasons, (
        f"CREATE_FAILED reason did not name the broken InstanceType value: {reasons!r}"
    )

    # --- positive control: same shape, a valid instance type ---
    good_name, good_status = _deploy_expect_terminal(ctx, _template("t3.micro"))
    assert good_status == "CREATE_COMPLETE", (
        f"positive control failed to deploy: {good_status}"
    )
    good_stack = cfn.describe_stacks(StackName=good_name)["Stacks"][0]
    good_outputs = {
        o["OutputKey"]: o["OutputValue"] for o in good_stack.get("Outputs", [])
    }
    good_instance = ec2.describe_instances(InstanceIds=[good_outputs["InstanceId"]])
    good_state = good_instance["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert good_state in {"pending", "running"}, (
        f"positive-control instance {good_outputs['InstanceId']} expected pending/running, got {good_state}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_expect_terminal(ctx, template: str) -> tuple[str, str]:
    """Create a stack and wait for ANY terminal status (success or rollback); does not raise
    on failure -- the caller asserts the specific expected outcome. Always registers cleanup."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=300.0,
        interval_s=5.0,
        description=f"CFN stack {name} terminal status",
    )
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
