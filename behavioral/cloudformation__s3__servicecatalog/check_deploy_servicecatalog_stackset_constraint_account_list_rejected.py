"""deploy-servicecatalog-stackset-constraint-account-list-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-stackset-constraint-account-list-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "servicecatalog"]

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

_REJECTED = (
    "Account 'self' should only contain numbers, unless AccountList is exactly [\"self\"]. "
    "(Service: ServiceCatalog, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
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
    body = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                 "Properties": {"Type": "String", "Value": "sim2real"}}},
    })
    s3.put_object(Bucket=bucket, Key="product.json", Body=body.encode())
    return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json"


def _template(portfolio_name, product_name, admin_role_name, exec_role_name, region, url,
             account_list):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Portfolio": {"Type": "AWS::ServiceCatalog::Portfolio", "Properties": {
                "DisplayName": portfolio_name, "ProviderName": "sim2real"}},
            "Product": {"Type": "AWS::ServiceCatalog::CloudFormationProduct", "Properties": {
                "Name": product_name, "Owner": "sim2real",
                "ProvisioningArtifactParameters": [{
                    "Name": "v1", "Type": "CLOUD_FORMATION_TEMPLATE",
                    "Info": {"LoadTemplateFromURL": url}}]}},
            "Assoc": {"Type": "AWS::ServiceCatalog::PortfolioProductAssociation", "Properties": {
                "PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"}}},
            "AdminRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": admin_role_name,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": exec_role_name,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"AWS": {"Fn::GetAtt": ["AdminRole", "Arn"]}},
                    "Action": "sts:AssumeRole"}]}}},
            "StackSetConstraint": {
                "Type": "AWS::ServiceCatalog::StackSetConstraint", "DependsOn": "Assoc",
                "Properties": {
                    "PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"},
                    "Description": "sim2real stackset constraint account list",
                    "AccountList": account_list, "RegionList": [region],
                    "AdminRole": {"Fn::GetAtt": ["AdminRole", "Arn"]},
                    "ExecutionRole": {"Ref": "ExecRole"},
                    "StackInstanceControl": "ALLOWED"}},
        },
        "Outputs": {
            "PortfolioRef": {"Value": {"Ref": "Portfolio"}},
            "ProductRef": {"Value": {"Ref": "Product"}},
            "StackSetConstraintRef": {"Value": {"Ref": "StackSetConstraint"}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation StackSetConstraint mixing AccountList ``self`` with an account id fails.

    The handler names the account list and nothing survives the rollback, while ``self`` alone
    deploys.
    """
    cf = ctx.client("cloudformation")
    sc = ctx.client("servicecatalog")
    s3 = ctx.client("s3")

    # Positive control: same template, AccountList given the one VALID value ["self"]. Both
    # stacks load the same hosted product template.
    url = _host_template(ctx, s3)
    good_portfolio = ctx.unique_name("sim2real-sc-pf-good-")
    good_product = ctx.unique_name("sim2real-sc-prod-good-")
    good_admin_role = ctx.unique_name("sim2real-sc-admin-good-")
    good_exec_role = ctx.unique_name("sim2real-sc-exec-good-")
    good_stack_name = ctx.unique_name("sim2real-sc-stackset-good-")
    good_template = _template(good_portfolio, good_product, good_admin_role, good_exec_role,
                              ctx.region, url, ["self"])
    good_id = create_stack(ctx, cf, good_stack_name, good_template,
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    good_out = stack_outputs(cf, good_id)
    listed = [c["ConstraintId"] for c in paginate(
        sc, "list_constraints_for_portfolio", "ConstraintDetails",
        PortfolioId=good_out["PortfolioRef"], ProductId=good_out["ProductRef"])]
    assert listed == [good_out["StackSetConstraintRef"]], f"control constraints {listed!r}"
    good_detail = sc.describe_constraint(Id=good_out["StackSetConstraintRef"])
    params = json.loads(good_detail["ConstraintParameters"])["Properties"]
    got = (good_detail["ConstraintDetail"]["Type"], params["AccountList"], params["RegionList"])
    assert got == ("STACKSET", ["self"], [ctx.region]), f"control constraint reads {got!r}"

    bad_portfolio = ctx.unique_name("sim2real-sc-pf-bad-")
    bad_product = ctx.unique_name("sim2real-sc-prod-bad-")
    bad_admin_role = ctx.unique_name("sim2real-sc-admin-bad-")
    bad_exec_role = ctx.unique_name("sim2real-sc-exec-bad-")
    bad_stack_name = ctx.unique_name("sim2real-sc-stackset-bad-")
    bad_template = _template(bad_portfolio, bad_product, bad_admin_role, bad_exec_role,
                             ctx.region, url, ["self", ctx.account])
    bad_id = create_stack(ctx, cf, bad_stack_name, bad_template,
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cf, bad_id), "StackSetConstraint")
    got = handler_reason(reason, ctx.account, bad_portfolio, bad_product)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Service Catalog, before this check's own delete_stack. Outputs
    # never populate on a rolled-back stack, so the physical ids come from the resource list.
    bad_resources = {r["LogicalResourceId"]: r.get("PhysicalResourceId")
                     for r in cf.describe_stack_resources(StackName=bad_id)["StackResources"]}
    bad_product_id, bad_portfolio_id = bad_resources["Product"], bad_resources["Portfolio"]
    gone = (
        "ResourceNotFoundException",
        f"There are no local or default products with id {bad_product_id}",
    )
    expect_error(lambda: sc.describe_product_as_admin(Id=bad_product_id), *gone)
    gone = (
        "ResourceNotFoundException",
        f"There are no local or default portfolios with id {bad_portfolio_id}",
    )
    expect_error(lambda: sc.describe_portfolio(Id=bad_portfolio_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
