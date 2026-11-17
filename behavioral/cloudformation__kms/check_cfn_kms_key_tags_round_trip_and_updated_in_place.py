"""cfn-kms-key-tags-round-trip-and-updated-in-place."""

from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "cfn-kms-key-tags-round-trip-and-updated-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
_PENDING_DAYS = 7


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN AWS::KMS::Key's Tags are returned exactly by ListResourceTags, a Tags-only
    update retags the same key in place, and the retagged set survives into pending deletion.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html
    """
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")
    stack_name = ctx.unique_name("sim2real-behav-cfnkms-tags-")

    tags_v1 = [
        {"Key": "sim2real", "Value": stack_name},
        {"Key": "CostCenter", "Value": "Example Corp"},
    ]
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(tags_v1)
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    _wait_stack(cfn, stack_id, "stack_create_complete")
    key_id = _physical_id(cfn, stack_id, "Key")

    got = _tag_set(kms, key_id)
    want = {("sim2real", stack_name), ("CostCenter", "Example Corp")}
    assert got == want, f"ListResourceTags after create: {got!r}, expected {want!r}"

    tags_v2 = [
        {"Key": "sim2real", "Value": stack_name},
        {"Key": "CostCenter", "Value": "AnyCompany"},
        {"Key": "Owner", "Value": "Jane Doe"},
    ]
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(tags_v2))
    _wait_stack(cfn, stack_id, "stack_update_complete")
    retagged_id = _physical_id(cfn, stack_id, "Key")
    assert retagged_id == key_id, (
        f"a Tags-only update must keep the same key, got {retagged_id!r} for {key_id!r}"
    )

    got = _tag_set(kms, key_id)
    want = {("sim2real", stack_name), ("CostCenter", "AnyCompany"), ("Owner", "Jane Doe")}
    assert got == want, f"ListResourceTags after the Tags-only update: {got!r}, expected {want!r}"

    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "stack_delete_complete")
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"DeleteStack must schedule the key, got KeyState={state!r}"

    got = _tag_set(kms, key_id)
    assert got == want, (
        f"ListResourceTags on a key pending deletion must still answer its last tags: "
        f"{got!r}, expected {want!r}"
    )


def _template(cfn_tags: list[dict]) -> str:
    return json.dumps(
        {
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real cfn key-tags test key",
                        "PendingWindowInDays": _PENDING_DAYS,
                        "Tags": cfn_tags,
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AccountAdmin",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": _ROOT},
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                }
            },
            "Outputs": {"KeyId": {"Value": {"Ref": "Key"}}},
        }
    )


def _tag_set(kms, key_id: str) -> set[tuple[str, str]]:
    tags_out = kms.get_paginator("list_resource_tags").paginate(KeyId=key_id).build_full_result()[
        "Tags"
    ]
    return {(t["TagKey"], t["TagValue"]) for t in tags_out}


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _wait_stack(cfn, stack_id: str, waiter_name: str) -> None:
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert not status.endswith("ROLLBACK") and not status.endswith("FAILED"), (
        f"{waiter_name} ended {status!r}"
    )


def _delete_stack(cfn, stack_id: str) -> None:
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "stack_delete_complete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
