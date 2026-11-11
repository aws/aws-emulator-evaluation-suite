"""deploy-cloudformation-cloudhsm-cluster-invalid-hsm-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudformation-cloudhsm-cluster-invalid-hsm-type-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudhsmv2"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_BAD_HSM_TYPE = "not-a-valid-hsm-type"
_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"
_HSM_TYPE = "hsm2m.medium"


def _template(hsm_type, tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
            }},
            "Cluster": {"Type": "AWS::CloudHSM::Cluster", "Properties": {
                "HsmType": hsm_type, "Mode": "NON_FIPS", "SubnetIds": [{"Ref": "Subnet"}],
                "Tags": [{"Key": "sim2real-hsm", "Value": tag_value}],
            }},
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SubnetAz": {"Value": {"Fn::GetAtt": ["Subnet", "AvailabilityZone"]}},
            "ClusterRef": {"Value": {"Ref": "Cluster"}},
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "ClusterId": {"Value": {"Fn::GetAtt": ["Cluster", "ClusterId"]}},
            "ClusterState": {"Value": {"Fn::GetAtt": ["Cluster", "State"]}},
            "ClusterVpcId": {"Value": {"Fn::GetAtt": ["Cluster", "VpcId"]}},
            "ClusterSecurityGroup": {"Value": {"Fn::GetAtt": ["Cluster", "SecurityGroup"]}},
            "ClusterBackupPolicy": {"Value": {"Fn::GetAtt": ["Cluster", "BackupPolicy"]}},
        },
    })


def _tagged(hsm, tag_value):
    """Every cluster carrying the templated sim2real-hsm tag value, across all pages."""
    return [c for c in paginate(hsm, "describe_clusters", "Clusters")
            if {"Key": "sim2real-hsm", "Value": tag_value} in c.get("TagList", [])]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation CloudHSM cluster whose HsmType breaks the registry pattern is refused by
    early validation naming the property, and no cluster exists; the same template with a valid
    HsmType deploys one.
    """
    cfn = ctx.client("cloudformation")
    hsm = ctx.client("cloudhsmv2")
    good_tag = ctx.unique_name("sim2real-cfnhsmgood-tag-")
    bad_tag = ctx.unique_name("sim2real-cfnhsmbad-tag-")

    # Positive control: the same template, HsmType given a valid value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnhsmgood-"),
                           _template(_HSM_TYPE, good_tag))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    control = [(c["ClusterId"], c["HsmType"], c["VpcId"]) for c in _tagged(hsm, good_tag)]
    assert control == [(out["ClusterId"], _HSM_TYPE, out["VpcId"])], f"control {control!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnhsmbad-"),
                          _template(_BAD_HSM_TYPE, bad_tag))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    want = [("Cluster", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"Property value [{_BAD_HSM_TYPE}] does not match pattern: "
             r"^((p|)hsm[0-9][a-z.]*\.[a-zA-Z]+)$",
             "/Resources/Cluster/Properties/HsmType")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Absence through CloudHSMv2 BEFORE this check's delete: no cluster carries the bad tag.
    assert _tagged(hsm, bad_tag) == [], "a cluster carries the rejected template's tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
