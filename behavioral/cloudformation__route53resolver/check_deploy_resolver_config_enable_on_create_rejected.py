"""deploy-resolver-config-enable-on-create-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-config-enable-on-create-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53resolver"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

def _template(flag: str) -> str:
    return f"""
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: String
Resources:
  ResolverConfig:
    Type: AWS::Route53Resolver::ResolverConfig
    Properties:
      ResourceId: !Ref VpcId
      AutodefinedReverseFlag: {flag}
Outputs:
  Ref:
    Value: !Ref ResolverConfig
  Id:
    Value: !GetAtt ResolverConfig.Id
"""


def _create_vpc(ctx, ec2):
    """A fresh tagged VPC; its resolver configs start at the account defaults."""
    name = ctx.unique_name("sim2real-r53r-rccfg-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name},
                                                            {"Key": "sim2real", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return vpc_id


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResolverConfig whose AutodefinedReverseFlag is ENABLE fails early validation on that
    property and leaves the VPC's resolver config at the value it had before the deploy, while
    the same template with DISABLE, the one value accepted on create, deploys and reads back.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")
    good_vpc = _create_vpc(ctx, ec2)
    bad_vpc = _create_vpc(ctx, ec2)

    # Positive control: the same template, AutodefinedReverseFlag given the accepted value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53r-rcok-"), _template("DISABLE"),
                           Parameters=[{"ParameterKey": "VpcId", "ParameterValue": good_vpc}])
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    good_cfg = r53r.get_resolver_config(ResourceId=good_vpc)["ResolverConfig"]
    got = (out["Ref"], out["Id"], good_cfg["ResourceId"], good_cfg["AutodefinedReverse"])
    want = (good_vpc, good_cfg["Id"], good_vpc, "DISABLED")
    assert got == want, f"control (Ref, GetAtt Id, ResourceId, AutodefinedReverse) {got!r}"

    before = r53r.get_resolver_config(ResourceId=bad_vpc)["ResolverConfig"]["AutodefinedReverse"]
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53r-rcbad-"), _template("ENABLE"),
                          Parameters=[{"ParameterKey": "VpcId", "ParameterValue": bad_vpc}])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want_rows = [("ResolverConfig", "PROPERTY_VALIDATION", "FAILED", "FAIL",
                  "ENABLE is not a valid enum value. Supported values: [DISABLE]",
                  "/Resources/ResolverConfig/Properties/AutodefinedReverseFlag")]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"

    # The rejected create never touched the VPC's config: it reads what it read before.
    after = r53r.get_resolver_config(ResourceId=bad_vpc)["ResolverConfig"]["AutodefinedReverse"]
    assert after == before, f"the bad VPC's AutodefinedReverse went {before!r} -> {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
