"""deploy-kms-replicakey-cfn-provisions-replica-then-tombstones."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-kms-replicakey-cfn-provisions-replica-then-tombstones"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


# ---- Check-specific: the template, then run(). ----

#: Candidate regions for the primary key: ctx.region is the replica's region (one endpoint), and
#: the first of these that differs is the primary's, so no region pair is hardcoded.
_REGION_POOL = ("us-east-1", "us-west-2", "us-west-1")
_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}


def _root_policy(*extra_statements: dict) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "EnableRootPermissions", "Effect": "Allow", "Principal": {"AWS": _ROOT},
             "Action": "kms:*", "Resource": "*"},
            *extra_statements,
        ],
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation AWS::KMS::ReplicaKey is a real replica of a CloudFormation multi-Region key.

    The primary lists the replica by ARN and Region, both keys read back their templated
    properties, the replica decrypts the primary's ciphertext, and both tombstone on delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-replicakey.html
    """
    replica_region = ctx.region
    primary_region = next(r for r in _REGION_POOL if r != replica_region)
    cfn_primary = ctx.client("cloudformation", region=primary_region)
    cfn_replica = ctx.client("cloudformation")
    kms_primary = ctx.client("kms", region=primary_region)
    kms_replica = ctx.client("kms")
    primary_description = "sim2real cfn multi-region primary key"
    replica_description = "sim2real cfn multi-region replica key"

    primary_template = json.dumps({
        "Resources": {
            "PrimaryKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": primary_description,
                    "MultiRegion": True,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": _root_policy(),
                },
            },
        },
        "Outputs": {
            "KeyId": {"Value": {"Ref": "PrimaryKey"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["PrimaryKey", "Arn"]}},
        },
    })
    primary_stack = create_stack(ctx, cfn_primary,
                                 ctx.unique_name("sim2real-behav-cfnrepl-primary-"),
                                 primary_template)
    status = wait_stack(cfn_primary, primary_stack)
    assert status == "CREATE_COMPLETE", f"primary key stack in {primary_region} ended {status!r}"
    primary_out = stack_outputs(cfn_primary, primary_stack)
    primary_key_id, primary_arn = primary_out["KeyId"], primary_out["KeyArn"]
    pmeta = kms_primary.describe_key(KeyId=primary_key_id)["KeyMetadata"]
    got = (pmeta["Arn"], pmeta["MultiRegion"], pmeta["Description"],
           pmeta["MultiRegionConfiguration"]["MultiRegionKeyType"])
    assert got == (primary_arn, True, primary_description, "PRIMARY"), f"primary reads {got!r}"

    marker_sid = ctx.unique_name("Sim2RealReplicaMarker").replace("-", "")
    replica_template = json.dumps({
        "Resources": {
            "ReplicaKey": {
                "Type": "AWS::KMS::ReplicaKey",
                "Properties": {
                    "PrimaryKeyArn": primary_arn,
                    "Description": replica_description,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": _root_policy({
                        "Sid": marker_sid, "Effect": "Allow", "Principal": {"AWS": _ROOT},
                        "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"], "Resource": "*",
                    }),
                },
            },
        },
        "Outputs": {
            "ReplicaKeyId": {"Value": {"Ref": "ReplicaKey"}},
            "ReplicaArn": {"Value": {"Fn::GetAtt": ["ReplicaKey", "Arn"]}},
        },
    })
    replica_stack = create_stack(ctx, cfn_replica,
                                 ctx.unique_name("sim2real-behav-cfnrepl-replica-"),
                                 replica_template)
    status = wait_stack(cfn_replica, replica_stack)
    assert status == "CREATE_COMPLETE", f"replica key stack in {replica_region} ended {status!r}"
    replica_out = stack_outputs(cfn_replica, replica_stack)
    replica_key_id, replica_arn = replica_out["ReplicaKeyId"], replica_out["ReplicaArn"]

    # Ref and GetAtt against an independent read: the replica the primary lists.
    replicas = kms_primary.describe_key(
        KeyId=primary_arn)["KeyMetadata"]["MultiRegionConfiguration"]["ReplicaKeys"]
    assert replicas == [{"Arn": replica_arn, "Region": replica_region}], (
        f"the primary lists replicas {replicas!r}; GetAtt Arn {replica_arn!r}"
    )
    partition = replica_stack.split(":")[1]
    want_arn = f"arn:{partition}:kms:{replica_region}:{ctx.account}:key/{replica_key_id}"
    assert replica_arn == want_arn, f"Ref {replica_key_id!r} does not name GetAtt Arn {replica_arn!r}"
    meta = kms_replica.describe_key(KeyId=replica_arn)["KeyMetadata"]
    got = (meta["KeyId"], meta["Description"], meta["MultiRegionConfiguration"]["MultiRegionKeyType"],
           meta["MultiRegionConfiguration"]["PrimaryKey"]["Arn"])
    want = (replica_key_id, replica_description, "REPLICA", primary_arn)
    assert got == want, f"replica reads {got!r}, expected {want!r}"

    policy_doc = json.loads(
        kms_replica.get_key_policy(KeyId=replica_key_id, PolicyName="default")["Policy"]
    )
    by_sid = {s["Sid"]: s for s in policy_doc["Statement"] if "Sid" in s}
    assert sorted(by_sid) == sorted(["EnableRootPermissions", marker_sid]), f"policy {policy_doc}"
    assert sorted(by_sid[marker_sid]["Action"]) == ["kms:DescribeKey", "kms:GetKeyPolicy"], (
        f"marker statement {by_sid[marker_sid]!r}"
    )

    plaintext = b"sim2real-cfn-replica-payload"
    ciphertext = kms_primary.encrypt(KeyId=primary_arn, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms_replica.decrypt(KeyId=replica_arn, CiphertextBlob=ciphertext)
    got = (decrypted["Plaintext"], decrypted["KeyId"])
    assert got == (plaintext, replica_arn), f"the replica decrypts to {got!r}"

    # Teardown is proven: the replica (it depends on the primary) first, then the primary. A
    # primary with a replica still scheduled tombstones to PendingReplicaDeletion.
    delete_stack(cfn_replica, replica_stack)
    state = kms_replica.describe_key(KeyId=replica_key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"the replica is {state!r} after its stack delete"
    delete_stack(cfn_primary, primary_stack)
    state = kms_primary.describe_key(KeyId=primary_key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingReplicaDeletion", f"the primary is {state!r} after its stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
