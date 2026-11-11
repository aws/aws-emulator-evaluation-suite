"""deploy-kms-replicakey-cfn-non-multiregion-primary-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-kms-replicakey-cfn-non-multiregion-primary-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule the directly created key's deletion; a key already pending deletion is done."""
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    if state not in ("PendingDeletion", "PendingReplicaDeletion"):
        kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


def _replica_template(primary_arn: str) -> str:
    return json.dumps({
        "Resources": {
            "ReplicaKey": {
                "Type": "AWS::KMS::ReplicaKey",
                "Properties": {
                    "PrimaryKeyArn": primary_arn,
                    "KeyPolicy": _root_policy(),
                    "PendingWindowInDays": 7,
                },
            },
        },
        "Outputs": {"ReplicaKeyId": {"Value": {"Ref": "ReplicaKey"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::KMS::ReplicaKey whose PrimaryKeyArn names a single-Region key rolls back.

    KMS refuses it as not multi-Region and the ordinary key stays a single-Region key with no
    replica, while the same template on a multi-Region primary deploys a REPLICA of it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-replicakey.html
    """
    replica_region = ctx.region
    primary_region = next(r for r in _REGION_POOL if r != replica_region)
    kms_primary = ctx.client("kms", region=primary_region)
    kms_replica = ctx.client("kms")
    cfn = ctx.client("cloudformation")
    tag = [{"TagKey": "sim2real", "TagValue": ctx.unique_name("sim2real-behav-cfnrepl-")}]

    # The one broken property: an ordinary (single-Region) key used as PrimaryKeyArn.
    ordinary = kms_primary.create_key(
        Description=ctx.unique_name("sim2real-behav-cfnrepl-ordinary-"), Tags=tag,
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _teardown_key(kms_primary, ordinary["Arn"]))
    primary = kms_primary.create_key(
        Description=ctx.unique_name("sim2real-behav-cfnrepl-ctrlprimary-"), MultiRegion=True,
        Tags=tag,
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _teardown_key(kms_primary, primary["Arn"]))
    assert (ordinary["MultiRegion"], primary["MultiRegion"]) == (False, True), (ordinary, primary)

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfnrepl-good-"),
                           _replica_template(primary["Arn"]))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfnrepl-bad-"),
                          _replica_template(ordinary["Arn"]))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "ReplicaKey")
    got = handler_reason(reason, ctx.account)
    arn = ordinary["Arn"].replace(ctx.account, "<account>")
    want = (f"{arn} is not a multi-region key. (Service: Kms, Status Code: 400, Request ID: "
            "<id>) (SDK Attempt Count: <n>)", "InvalidRequest")
    assert got == want, f"handler reason {got!r}, expected {want!r}"

    # Rollback absence through KMS: the ordinary key is still single-Region, with no replica.
    after = kms_primary.describe_key(KeyId=ordinary["Arn"])["KeyMetadata"]
    got = (after["MultiRegion"], "MultiRegionConfiguration" in after, after["KeyState"])
    assert got == (False, False, "Enabled"), f"the ordinary key reads {after!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    replica_key_id = stack_outputs(cfn, good_id)["ReplicaKeyId"]
    meta = kms_replica.describe_key(KeyId=replica_key_id)["KeyMetadata"]
    got = (meta["KeyId"], meta["MultiRegionConfiguration"]["MultiRegionKeyType"],
           meta["MultiRegionConfiguration"]["PrimaryKey"]["Arn"])
    assert got == (replica_key_id, "REPLICA", primary["Arn"]), f"the control replica reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
