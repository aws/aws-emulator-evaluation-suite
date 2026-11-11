"""deploy-ec2-keypair-placementgroup-appstatuscheck-read-back-and-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-keypair-placementgroup-appstatuscheck-read-back-and-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(key_name: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {"Type": "AWS::EC2::KeyPair", "Properties": {
                "KeyName": key_name, "KeyType": "rsa",
            }},
            "Pg": {"Type": "AWS::EC2::PlacementGroup", "Properties": {"Strategy": "cluster"}},
            "Asc": {"Type": "AWS::EC2::ApplicationStatusCheck", "Properties": {
                "Protocol": "http", "Port": 8080, "Path": "/healthz",
            }},
        },
        "Outputs": {
            "KeyName": {"Value": {"Ref": "Key"}},
            "KeyPairId": {"Value": {"Fn::GetAtt": ["Key", "KeyPairId"]}},
            "KeyFingerprint": {"Value": {"Fn::GetAtt": ["Key", "KeyFingerprint"]}},
            "PgGroupName": {"Value": {"Ref": "Pg"}},
            "PgGroupId": {"Value": {"Fn::GetAtt": ["Pg", "GroupId"]}},
            "AscArn": {"Value": {"Ref": "Asc"}},
            "AscId": {"Value": {"Fn::GetAtt": ["Asc", "ApplicationStatusCheckId"]}},
            "AscArnAtt": {"Value": {"Fn::GetAtt": ["Asc", "Arn"]}},
        },
    }


def _all_status_checks(ec2) -> list[dict]:
    """Every DescribeApplicationStatusChecks entry across pages (the operation has no paginator)."""
    out, kw = [], {}
    while True:
        page = ec2.describe_application_status_checks(**kw)
        out.extend(page.get("ApplicationStatusChecks", []))
        if not page.get("NextToken"):
            return out
        kw = {"NextToken": page["NextToken"]}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN key pair, placement group and application status check each read back through EC2's
    own API with every property and Fn::GetAtt value the template carries, and deleting the stack
    makes EC2 answer each physical id with its own not-found signal.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    key_name = ctx.unique_name("sim2real-xsvc-std4-key-")
    stack_name = ctx.unique_name("sim2real-xsvc-std4-")
    stack_id = create_stack(ctx, cfn, stack_name, json.dumps(_template(key_name)))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Each Ref against a read keyed by the GetAtt id, never by the Ref itself.
    keys = ec2.describe_key_pairs(KeyPairIds=[outputs["KeyPairId"]])["KeyPairs"]
    assert len(keys) == 1, f"DescribeKeyPairs by id returned {keys!r}"
    key = keys[0]
    assert key["KeyName"] == outputs["KeyName"] == key_name, f"EC2 reports key name {key['KeyName']!r}, expected {key_name!r}"
    assert key["KeyType"] == "rsa", f"EC2 reports key type {key['KeyType']!r}, expected 'rsa'"
    assert key["KeyPairId"] == outputs["KeyPairId"], (
        f"EC2's KeyPairId {key['KeyPairId']!r} disagrees with the stack's Fn::GetAtt value "
        f"{outputs['KeyPairId']!r}"
    )
    assert key["KeyFingerprint"] == outputs["KeyFingerprint"], (
        f"EC2's KeyFingerprint {key['KeyFingerprint']!r} disagrees with the stack's Fn::GetAtt "
        f"value {outputs['KeyFingerprint']!r}"
    )

    pgs = ec2.describe_placement_groups(GroupIds=[outputs["PgGroupId"]])["PlacementGroups"]
    assert len(pgs) == 1, f"DescribePlacementGroups by id returned {pgs!r}"
    pg = pgs[0]
    assert pg["GroupName"] == outputs["PgGroupName"], (
        f"EC2's GroupName {pg['GroupName']!r} disagrees with the Ref {outputs['PgGroupName']!r}"
    )
    assert pg["Strategy"] == "cluster", f"EC2 reports placement strategy {pg['Strategy']!r}, expected 'cluster'"
    assert pg["GroupId"] == outputs["PgGroupId"], (
        f"EC2's GroupId {pg['GroupId']!r} disagrees with the stack's Fn::GetAtt value "
        f"{outputs['PgGroupId']!r}"
    )

    ascs = [a for a in _all_status_checks(ec2) if a["ApplicationStatusCheckId"] == outputs["AscId"]]
    assert len(ascs) == 1, f"DescribeApplicationStatusChecks lists {ascs!r} for {outputs['AscId']!r}"
    asc = ascs[0]
    want_arn = (f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:"
                f"application-status-check/{outputs['AscId']}")
    assert (outputs["AscArn"], outputs["AscArnAtt"]) == (want_arn, want_arn), (
        f"Ref {outputs['AscArn']!r} / GetAtt Arn {outputs['AscArnAtt']!r}, expected {want_arn!r}"
    )
    assert asc["Protocol"] == "http", f"EC2 reports protocol {asc['Protocol']!r}, expected 'http'"
    assert asc["Port"] == 8080, f"EC2 reports port {asc['Port']!r}, expected 8080"
    assert asc["Path"] == "/healthz", f"EC2 reports path {asc['Path']!r}, expected '/healthz'"
    assert asc["ApplicationStatusCheckId"] == outputs["AscId"], (
        f"EC2's ApplicationStatusCheckId {asc['ApplicationStatusCheckId']!r} disagrees with the "
        f"stack's Fn::GetAtt value {outputs['AscId']!r}"
    )

    delete_stack(cfn, stack_id)
    key_pairs_gone = ("InvalidKeyPair.NotFound", f"The key pair '{key_name}' does not exist")
    expect_error(lambda: ec2.describe_key_pairs(KeyNames=[outputs["KeyName"]]), *key_pairs_gone)
    placement_groups_gone = (
        "InvalidPlacementGroup.Unknown",
        f"The Placement Group '{outputs['PgGroupName']}' is unknown.",
    )
    expect_error(lambda: ec2.describe_placement_groups(GroupNames=[outputs["PgGroupName"]]),
                 *placement_groups_gone)

    remaining = ec2.describe_application_status_checks(
        ApplicationStatusCheckIds=[outputs["AscId"]])["ApplicationStatusChecks"]
    assert remaining == [], (
        f"the application status check {outputs['AscId']!r} is still described after the stack "
        f"delete: {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
