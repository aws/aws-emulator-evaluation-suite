"""cfn-ssm-patch-baseline-wrong-tag-filter-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-patch-baseline-wrong-tag-filter-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A patch-baseline association whose tag filter matches no instance resolves to zero targets
    (ResourceCountByStatus "{}") and no matching instance, while a sibling association using the
    instance's actual tag value resolves to at least one target (positive control)."""
    match_value = ctx.unique_name("sim2real-pg-match-")
    mismatch_value = ctx.unique_name("sim2real-pg-mismatch-")

    template = json.dumps(
        {
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAM,
                }
            },
            "Resources": {
                "InstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                        ],
                    },
                },
                "InstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
                },
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "IamInstanceProfile": {"Ref": "InstanceProfile"},
                        "Tags": _xsvc_tags_kv()
                        + [{"Key": "Patch Group", "Value": match_value}],
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "PatchBaseline": {
                    "Type": "AWS::SSM::PatchBaseline",
                    "Properties": {
                        "Name": ctx.unique_name("sim2real-xsvc-pb-"),
                        "OperatingSystem": "AMAZON_LINUX_2023",
                        "ApprovalRules": {
                            "PatchRules": [
                                {
                                    "PatchFilterGroup": {
                                        "PatchFilters": [
                                            {
                                                "Key": "CLASSIFICATION",
                                                "Values": ["Security"],
                                            }
                                        ]
                                    },
                                    "ApproveAfterDays": 0,
                                    "ComplianceLevel": "CRITICAL",
                                }
                            ]
                        },
                        "PatchGroups": [match_value],
                    },
                },
                "AssocGood": {
                    "Type": "AWS::SSM::Association",
                    "Properties": {
                        "Name": "AWS-RunPatchBaseline",
                        "Targets": [
                            {"Key": "tag:Patch Group", "Values": [match_value]}
                        ],
                        "Parameters": {"Operation": ["Scan"]},
                    },
                },
                "AssocBad": {
                    "Type": "AWS::SSM::Association",
                    "Properties": {
                        "Name": "AWS-RunPatchBaseline",
                        "Targets": [
                            {"Key": "tag:Patch Group", "Values": [mismatch_value]}
                        ],
                        "Parameters": {"Operation": ["Scan"]},
                    },
                },
            },
            "Outputs": {
                "InstanceId": {"Value": {"Ref": "Instance"}},
                "AssocGoodId": {"Value": {"Ref": "AssocGood"}},
                "AssocBadId": {"Value": {"Ref": "AssocBad"}},
            },
        }
    )

    stack = _deploy_cfn(ctx, template, timeout_s=240)
    instance_id = stack["outputs"]["InstanceId"]
    assoc_good = stack["outputs"]["AssocGoodId"]
    assoc_bad = stack["outputs"]["AssocBadId"]

    ssm = ctx.client("ssm")

    def _ping_status() -> str:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else "NOT_REGISTERED"

    _poll_until(
        _ping_status,
        lambda s: s == "Online",
        timeout_s=360.0,
        interval_s=10.0,
        description="SSM Agent registers instance as Online",
    )

    def _first_execution(association_id: str) -> dict[str, Any] | None:
        execs = ssm.describe_association_executions(AssociationId=association_id)[
            "AssociationExecutions"
        ]
        return execs[0] if execs else None

    good_exec = _poll_until(
        lambda: _first_execution(assoc_good),
        lambda e: e is not None and e["ResourceCountByStatus"] != "{}",
        timeout_s=180.0,
        interval_s=5.0,
        description="matching-tag association resolves at least one target",
    )
    bad_exec = _poll_until(
        lambda: _first_execution(assoc_bad),
        lambda e: e is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description="mismatched-tag association records an execution",
    )

    # ResourceCountByStatus is documented as a Java-map-style string, e.g. "{Success=1}";
    # zero matched targets renders as the empty map "{}".
    assert bad_exec["ResourceCountByStatus"] == "{}", (
        f"mismatched-tag association unexpectedly targeted resources: {bad_exec}"
    )
    assert good_exec["ResourceCountByStatus"] != "{}", (
        f"matching-tag association unexpectedly targeted zero resources: {good_exec}"
    )

    # ground-truth cross-check: the EC2 tag the bad association filters on is not present on
    # any real instance, and the EC2 tag the good association filters on is present on exactly
    # the one instance we created.
    ec2 = ctx.client("ec2")
    bad_matches = ec2.describe_instances(
        Filters=[{"Name": "tag:Patch Group", "Values": [mismatch_value]}]
    )["Reservations"]
    good_matches = ec2.describe_instances(
        Filters=[{"Name": "tag:Patch Group", "Values": [match_value]}]
    )["Reservations"]
    assert bad_matches == []
    assert any(
        i["InstanceId"] == instance_id for r in good_matches for i in r["Instances"]
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
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
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
