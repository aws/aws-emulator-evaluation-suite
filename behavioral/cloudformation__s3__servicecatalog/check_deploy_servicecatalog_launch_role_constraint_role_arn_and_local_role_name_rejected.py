"""deploy-servicecatalog-launch-role-constraint-role-arn-and-local-role-name-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-launch-role-constraint-role-arn-and-local-role-name-rejected"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, timeout_s, description, interval_s=5.0):
    """Call ``probe`` until ``done(result)``; return the result.

    A spent run budget raises TimeoutError (not graded); the wait's own deadline fails the check.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s: {last!r}")
        time.sleep(interval_s)


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    return _poll(
        ctx,
        lambda: cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"],
        lambda status: status in terminal,
        timeout_s,
        f"stack {stack_id} reaching one of {sorted(terminal)}",
        interval_s=2.0,
    )


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating, updating or rolling back is first waited out; a failure names each
    resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        wait_stack(ctx, cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
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
    ctx.on_cleanup(
        lambda: delete_stack(ctx, cf, created["StackId"]) if created.get("StackId") else None
    )
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


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

_SCHEMA_REASON = (
    "Properties validation failed for resource LaunchRoleConstraint with message:\n"
    "#: #: only 1 subschema matches out of 2\n"
    "#: #: 2 subschemas matched instead of one"
)


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


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _physical_id(events, logical_id):
    """The physical id on the single CREATE_COMPLETE row of ``logical_id``."""
    rows = [
        e["PhysicalResourceId"]
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_COMPLETE"
    ]
    assert len(rows) == 1, f"expected one CREATE_COMPLETE row for {logical_id}, got {rows!r}"
    return rows[0]


def _template(portfolio_name, product_name, role_name, url, *, with_role_arn=True):
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
            "LaunchRoleConstraintRef": {"Value": {"Ref": "LaunchRoleConstraint"}},
        },
    }
    if with_role_arn:
        # Both RoleArn and LocalRoleName: the resource's own schema allows exactly one.
        template["Resources"]["LaunchRoleConstraint"]["Properties"]["RoleArn"] = {
            "Fn::GetAtt": ["LaunchRole", "Arn"]
        }
    return json.dumps(template)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LaunchRoleConstraint that sets both RoleArn and LocalRoleName fails its
    property schema and the stack rolls back, deleting its portfolio and product; the same
    template with LocalRoleName only deploys and stores exactly that local role name."""
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sc = ctx.client("servicecatalog")

    url = _host_template(ctx, s3)

    portfolio_name = ctx.unique_name("sim2real-sc-pf-")
    product_name = ctx.unique_name("sim2real-sc-prod-")
    role_name = ctx.unique_name("sim2real-sc-launch-")
    stack_name = ctx.unique_name("sim2real-sc-lrc-both-")
    template = _template(portfolio_name, product_name, role_name, url)
    stack_id = create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(ctx, cf, stack_id, timeout_s=300.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with both RoleArn and LocalRoleName set ended {status!r}, expected 'ROLLBACK_COMPLETE'"
    )

    events = stack_events(cf, stack_id)
    failures = [
        e
        for e in events
        if e["LogicalResourceId"] == "LaunchRoleConstraint"
        and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failures) == 1, (
        f"expected exactly one CREATE_FAILED event for LaunchRoleConstraint, found {failures!r}"
    )
    assert failures[0]["ResourceStatusReason"] == _SCHEMA_REASON, (
        f"LaunchRoleConstraint's CREATE_FAILED reason is "
        f"{failures[0]['ResourceStatusReason']!r}, expected {_SCHEMA_REASON!r}"
    )

    # The portfolio and product created before the constraint failed are gone after the rollback.
    portfolio_id = _physical_id(events, "Portfolio")
    product_id = _physical_id(events, "Product")
    rolled_back = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if e["LogicalResourceId"] in ("Portfolio", "Product")
        and e["ResourceStatus"] == "DELETE_COMPLETE"
    ]
    assert sorted(rolled_back) == [
        ("Portfolio", "DELETE_COMPLETE"),
        ("Product", "DELETE_COMPLETE"),
    ], f"expected one DELETE_COMPLETE row each for Portfolio and Product, found {rolled_back!r}"
    expect_error(
        lambda: sc.describe_portfolio(Id=portfolio_id),
        "ResourceNotFoundException",
        f"There are no local or default portfolios with id {portfolio_id}",
    )
    expect_error(
        lambda: sc.describe_product_as_admin(Id=product_id),
        "ResourceNotFoundException",
        f"There are no local or default products with id {product_id}",
    )

    # Positive control: the same template with LocalRoleName only deploys.
    ok_role = ctx.unique_name("sim2real-sc-launch-")
    ok_id = create_stack(
        ctx,
        cf,
        ctx.unique_name("sim2real-sc-lrc-ok-"),
        _template(
            ctx.unique_name("sim2real-sc-pf-"),
            ctx.unique_name("sim2real-sc-prod-"),
            ok_role,
            url,
            with_role_arn=False,
        ),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(ctx, cf, ok_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}, expected CREATE_COMPLETE"
    out = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=ok_id)["Stacks"][0].get("Outputs", [])
    }
    described = sc.describe_constraint(Id=out["LaunchRoleConstraintRef"])
    detail = described["ConstraintDetail"]
    got = (
        detail["Type"],
        detail["PortfolioId"],
        detail["ProductId"],
        json.loads(described["ConstraintParameters"]),
    )
    want = ("LAUNCH", out["PortfolioRef"], out["ProductRef"], {"LocalRoleName": ok_role})
    assert got == want, f"control DescribeConstraint {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
