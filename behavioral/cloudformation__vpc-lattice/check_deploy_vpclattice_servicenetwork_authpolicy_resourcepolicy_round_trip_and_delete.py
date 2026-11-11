"""deploy-vpclattice-servicenetwork-authpolicy-resourcepolicy-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-servicenetwork-authpolicy-resourcepolicy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "vpc-lattice"]

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


# ---- Check-specific: the template, then run(). ----

def _auth_policy(principal):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "sim2real-allow-invoke", "Effect": "Allow",
                       "Principal": {"AWS": principal}, "Action": "vpc-lattice-svcs:Invoke",
                       "Resource": "*"}],
    }


def _resource_policy(principal, resource):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "sim2real-allow-share", "Effect": "Allow",
                       "Principal": {"AWS": principal},
                       "Action": "vpc-lattice:CreateServiceNetworkVpcAssociation",
                       "Resource": resource}],
    }


def _template(name):
    root = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Sn": {"Type": "AWS::VpcLattice::ServiceNetwork",
                   "Properties": {"Name": name, "AuthType": "AWS_IAM",
                                  "Tags": [{"Key": "sim2real-resource", "Value": name}]}},
            "Auth": {"Type": "AWS::VpcLattice::AuthPolicy",
                     "Properties": {"ResourceIdentifier": {"Ref": "Sn"},
                                    "Policy": _auth_policy(root)}},
            "Rp": {"Type": "AWS::VpcLattice::ResourcePolicy",
                   "Properties": {"ResourceArn": {"Fn::GetAtt": ["Sn", "Arn"]},
                                  "Policy": _resource_policy(root, {"Fn::GetAtt": ["Sn", "Arn"]})}},
        },
        "Outputs": {
            "SnArn": {"Value": {"Ref": "Sn"}},
            "SnId": {"Value": {"Fn::GetAtt": ["Sn", "Id"]}},
            "AuthRef": {"Value": {"Ref": "Auth"}},
            "AuthState": {"Value": {"Fn::GetAtt": ["Auth", "State"]}},
            "RpRef": {"Value": {"Ref": "Rp"}},
        },
    })


def _own_tags(vl, arn):
    tags_map = vl.list_tags_for_resource(resourceArn=arn).get("tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


def _listed_arns(vl, op, name, **kw):
    return [i["arn"] for i in paginate(vl, op, "items", **kw) if i.get("name") == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPC Lattice service network with an auth policy and a resource policy reads back.

    Ref, AuthType, tags and both policy documents match VPC Lattice, and deleting the stack makes
    the network and both policies unreadable.
    """
    vl = ctx.client("vpc-lattice")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-vpclattice-sn-stack-")
    sn_name = ctx.unique_name("sim2real-vpclattice-sn-")

    stack_id = create_stack(ctx, cfn, stack, _template(sn_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    sn_arn, sn_id = out["SnArn"], out["SnId"]
    root = f"arn:{partition}:iam::{ctx.account}:root"

    # Ref == the listed network's ARN and the documented format; both policies' Refs name it.
    assert _listed_arns(vl, "list_service_networks", sn_name) == [sn_arn], "service network Ref"
    want_arn = f"arn:{partition}:vpc-lattice:{ctx.region}:{ctx.account}:servicenetwork/{sn_id}"
    assert (sn_arn, out["AuthRef"], out["RpRef"]) == (want_arn,) * 3, (
        f"Refs {sn_arn!r}, {out['AuthRef']!r}, {out['RpRef']!r}, expected {want_arn!r}"
    )
    sn = vl.get_service_network(serviceNetworkIdentifier=sn_arn)
    assert (sn["id"], sn["name"], sn["authType"]) == (sn_id, sn_name, "AWS_IAM"), (
        f"GetServiceNetwork reads {sn!r}"
    )
    sn_tags = _own_tags(vl, sn_arn)
    assert sn_tags == {"sim2real": stack, "sim2real-resource": sn_name}, f"tags {sn_tags!r}"

    auth = vl.get_auth_policy(resourceIdentifier=sn_arn)
    got = (auth["state"], out["AuthState"], json.loads(auth["policy"]))
    assert got == ("Active", "Active", _auth_policy(root)), f"auth policy reads {got!r}"
    rp = json.loads(vl.get_resource_policy(resourceArn=sn_arn)["policy"])
    assert rp == _resource_policy(root, sn_arn), f"resource policy reads {rp!r}"

    # Both policies live on the network, so the network's delete is what removes them.
    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", f"ServiceNetwork {sn_id} cannot be found.")
    expect_error(lambda: vl.get_service_network(serviceNetworkIdentifier=sn_id), *gone)
    expect_error(lambda: vl.get_auth_policy(resourceIdentifier=sn_id), *gone)
    expect_error(lambda: vl.get_resource_policy(resourceArn=sn_arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
