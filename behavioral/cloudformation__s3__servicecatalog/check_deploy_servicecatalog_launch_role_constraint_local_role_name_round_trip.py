"""deploy-servicecatalog-launch-role-constraint-local-role-name-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-launch-role-constraint-local-role-name-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "servicecatalog"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 300.0


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
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack(cf, created["StackId"]) if created.get("StackId") else None)
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
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


# ---- Check-specific: the template, then run(). ----

_LAUNCH_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "servicecatalog.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _host_template(ctx, s3) -> str:
    """Publish a trivial product template to a bucket this check owns and deletes; return the
    S3 URL Service Catalog loads it from (the stack cannot write the object itself)."""
    bucket = ctx.unique_name("sim2real-sc-tpl-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)

    def _empty_and_delete() -> None:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Param": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Type": "String", "Value": "sim2real"},
                }
            },
        }
    )
    s3.put_object(Bucket=bucket, Key="product.json", Body=body.encode())
    return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json"


def _template(portfolio_name, product_name, role_name, url):
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Portfolio": {
                "Type": "AWS::ServiceCatalog::Portfolio",
                "Properties": {"DisplayName": portfolio_name, "ProviderName": "sim2real"},
            },
            "Product": {
                "Type": "AWS::ServiceCatalog::CloudFormationProduct",
                "Properties": {
                    "Name": product_name,
                    "Owner": "sim2real",
                    "ProvisioningArtifactParameters": [
                        {
                            "Name": "v1",
                            "Type": "CLOUD_FORMATION_TEMPLATE",
                            "Info": {"LoadTemplateFromURL": url},
                        }
                    ],
                },
            },
            "Assoc": {
                "Type": "AWS::ServiceCatalog::PortfolioProductAssociation",
                "Properties": {
                    "PortfolioId": {"Ref": "Portfolio"},
                    "ProductId": {"Ref": "Product"},
                },
            },
            "LaunchRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": role_name, "AssumeRolePolicyDocument": _LAUNCH_TRUST},
            },
            "LaunchRoleConstraint": {
                "Type": "AWS::ServiceCatalog::LaunchRoleConstraint",
                "DependsOn": "Assoc",
                "Properties": {
                    "PortfolioId": {"Ref": "Portfolio"},
                    "ProductId": {"Ref": "Product"},
                    "LocalRoleName": {"Ref": "LaunchRole"},
                },
            },
        },
        "Outputs": {
            "PortfolioRef": {"Value": {"Ref": "Portfolio"}},
            "ProductRef": {"Value": {"Ref": "Product"}},
            "LaunchRoleRef": {"Value": {"Ref": "LaunchRole"}},
            "LaunchRoleConstraintRef": {"Value": {"Ref": "LaunchRoleConstraint"}},
        },
    }
    return json.dumps(template)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LaunchRoleConstraint set with LocalRoleName (not RoleArn) reads back
    that exact local role name through DescribeConstraint's ConstraintParameters."""
    cf = ctx.client("cloudformation")
    sc = ctx.client("servicecatalog")
    s3 = ctx.client("s3")

    portfolio_name = ctx.unique_name("sim2real-sc-pf-")
    product_name = ctx.unique_name("sim2real-sc-prod-")
    role_name = ctx.unique_name("sim2real-sc-launch-")[:64]
    stack_name = ctx.unique_name("sim2real-sc-lrc-")

    url = _host_template(ctx, s3)
    template = _template(portfolio_name, product_name, role_name, url)
    stack_id = create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    portfolio_id, product_id = out["PortfolioRef"], out["ProductRef"]
    constraint_id = out["LaunchRoleConstraintRef"]

    assert out["LaunchRoleRef"] == role_name, (
        f"AWS::IAM::Role Ref {out['LaunchRoleRef']!r} != the templated RoleName {role_name!r}"
    )

    # The constraint, found independently through the portfolio/product it was created for.
    constraints = paginate(
        sc,
        "list_constraints_for_portfolio",
        "ConstraintDetails",
        PortfolioId=portfolio_id,
        ProductId=product_id,
    )
    constraint_types = {c["ConstraintId"]: c["Type"] for c in constraints}
    assert constraint_types == {constraint_id: "LAUNCH"}, (
        f"ListConstraintsForPortfolio reports {constraint_types!r}, expected only "
        f"{constraint_id!r} of type 'LAUNCH'"
    )

    described = sc.describe_constraint(Id=constraint_id)
    assert described["ConstraintDetail"]["Type"] == "LAUNCH", (
        f"DescribeConstraint Type {described['ConstraintDetail']['Type']!r}, expected 'LAUNCH'"
    )
    assert described["ConstraintDetail"]["PortfolioId"] == portfolio_id, (
        f"DescribeConstraint PortfolioId {described['ConstraintDetail']['PortfolioId']!r} != "
        f"{portfolio_id!r}"
    )
    assert described["ConstraintDetail"]["ProductId"] == product_id, (
        f"DescribeConstraint ProductId {described['ConstraintDetail']['ProductId']!r} != "
        f"{product_id!r}"
    )
    params = json.loads(described["ConstraintParameters"])
    assert params == {"LocalRoleName": role_name}, (
        f"LaunchRoleConstraint's stored parameters are {params!r}, expected exactly "
        f"{{'LocalRoleName': {role_name!r}}} from the template's LocalRoleName property, with no "
        f"RoleArn resolved for it"
    )

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException", f"Constraint {constraint_id} not found.")
    try:
        sc.describe_constraint(Id=constraint_id)
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == gone, (
            f"after stack delete, DescribeConstraint answered {got!r}, expected {gone!r}"
        )
    else:
        raise AssertionError("after stack delete, DescribeConstraint still found the constraint")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
