"""deploy-servicecatalog-provisioned-product-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-provisioned-product-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "servicecatalog", "sts"]

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

def _own_tags(rows):
    """Service Catalog ``Tags`` rows as {key: value}, without the ``aws:`` system tags."""
    return {r["Key"]: r["Value"] for r in rows if not r["Key"].startswith("aws:")}


def _host_template(ctx, s3) -> str:
    """Publish a product template that echoes its parameter to a bucket this check owns and
    deletes; return the S3 URL Service Catalog loads it from (the stack cannot write the
    object itself)."""
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
    body = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Greeting": {"Type": "String", "Default": "sim2real"}},
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                 "Properties": {"Type": "String", "Value": {"Ref": "Greeting"}}}},
        "Outputs": {"Echo": {"Value": {"Ref": "Greeting"}}},
    })
    s3.put_object(Bucket=bucket, Key="product.json", Body=body.encode())
    return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json"


def _template(portfolio_name, product_name, who, pp_name, greeting, url, children=True):
    template = {
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
            "PrincipalAssoc": {"Type": "AWS::ServiceCatalog::PortfolioPrincipalAssociation",
                "Properties": {"PortfolioId": {"Ref": "Portfolio"}, "PrincipalType": "IAM",
                                "PrincipalARN": who}},
            "PP": {"Type": "AWS::ServiceCatalog::CloudFormationProvisionedProduct",
                "DependsOn": ["Assoc", "PrincipalAssoc"],
                "Properties": {
                    "ProductId": {"Ref": "Product"}, "ProvisioningArtifactName": "v1",
                    "ProvisionedProductName": pp_name,
                    "ProvisioningParameters": [{"Key": "Greeting", "Value": greeting}]}},
        },
        "Outputs": {
            "PortfolioRef": {"Value": {"Ref": "Portfolio"}},
            "ProductRef": {"Value": {"Ref": "Product"}},
            "PPRef": {"Value": {"Ref": "PP"}},
            "PPId": {"Value": {"Fn::GetAtt": ["PP", "ProvisionedProductId"]}},
            "PPRecordId": {"Value": {"Fn::GetAtt": ["PP", "RecordId"]}},
            "PPStackArn": {"Value": {"Fn::GetAtt": ["PP", "CloudformationStackArn"]}},
        },
    }
    if not children:
        for key in ("Assoc", "PrincipalAssoc", "PP"):
            del template["Resources"][key]
        template["Outputs"] = {k: v for k, v in template["Outputs"].items()
                               if k in ("PortfolioRef", "ProductRef")}
    return json.dumps(template)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Service Catalog provisioned product reaches AVAILABLE with its parameter.

    Its nested stack carries the parameter; an update dropping it and both associations removes
    them while product and portfolio answer, and the stack delete removes those two.
    """
    cf = ctx.client("cloudformation")
    sc = ctx.client("servicecatalog")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    who = sts.get_caller_identity()["Arn"]

    portfolio_name = ctx.unique_name("sim2real-sc-pf-")
    product_name = ctx.unique_name("sim2real-sc-prod-")
    pp_name = ctx.unique_name("sim2real-sc-pp-")
    stack_name = ctx.unique_name("sim2real-sc-pp-stack-")
    greeting = ctx.unique_name("sim2real-sc-greet-")

    url = _host_template(ctx, s3)
    template = _template(portfolio_name, product_name, who, pp_name, greeting, url)
    stack_id = create_stack(ctx, cf, stack_name, template)
    status = wait_stack(cf, stack_id, timeout_s=400.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    product_id, pp_id = out["ProductRef"], out["PPId"]
    assert out["PPRef"] == pp_id, f"PP Ref {out['PPRef']!r} != GetAtt ProvisionedProductId {pp_id!r}"

    # An independent list, never a read keyed by the Ref: SearchProvisionedProducts by name.
    found = sc.search_provisioned_products(
        Filters={"SearchQuery": [f"name:{pp_name}"]}, PageSize=100)["ProvisionedProducts"]
    assert [p["Id"] for p in found] == [pp_id], (
        f"SearchProvisionedProducts for {pp_name!r} found {found!r}, expected exactly {pp_id!r}"
    )

    detail = sc.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
    assert (detail["Status"], detail["Type"], detail["ProductId"], detail["Name"]) == (
        "AVAILABLE", "CFN_STACK", product_id, pp_name
    ), f"DescribeProvisionedProduct returned {detail!r}"
    assert detail["LastRecordId"] == out["PPRecordId"], (
        f"LastRecordId {detail['LastRecordId']!r} != GetAtt RecordId {out['PPRecordId']!r}"
    )
    record = sc.describe_record(Id=out["PPRecordId"])["RecordDetail"]
    assert (record["ProvisionedProductId"], record["Status"]) == (pp_id, "SUCCEEDED"), (
        f"DescribeRecord returned {record!r}"
    )

    # The nested stack Service Catalog launched, read through CloudFormation by the ARN it named.
    nested = cf.describe_stacks(StackName=out["PPStackArn"])["Stacks"][0]
    assert nested["StackStatus"] == "CREATE_COMPLETE", (
        f"nested stack is {nested['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    nested_outputs = {o["OutputKey"]: o["OutputValue"] for o in nested.get("Outputs", [])}
    assert nested_outputs.get("Echo") == greeting, (
        f"nested stack Echo output {nested_outputs.get('Echo')!r} != {greeting!r} — the "
        f"ProvisioningParameters value did not reach the deployed template"
    )
    nested_resources = {r["LogicalResourceId"]: r["ResourceStatus"] for r in
                        cf.describe_stack_resources(StackName=out["PPStackArn"])["StackResources"]}
    assert nested_resources == {"Param": "CREATE_COMPLETE"}, (
        f"nested stack resources {nested_resources!r}"
    )

    # Portfolio, product and both associations, through Service Catalog's own reads.
    portfolio_id = out["PortfolioRef"]
    listed = [p for p in paginate(sc, "list_portfolios", "PortfolioDetails")
              if p["DisplayName"] == portfolio_name]
    assert [(p["Id"], p["ProviderName"]) for p in listed] == [(portfolio_id, "sim2real")], (
        f"ListPortfolios for {portfolio_name!r} found {listed!r}"
    )
    described = sc.describe_product_as_admin(Id=product_id)
    summary = described["ProductViewDetail"]["ProductViewSummary"]
    got = (summary["Name"], summary["Owner"],
           [a["Name"] for a in described["ProvisioningArtifactSummaries"]])
    assert got == (product_name, "sim2real", ["v1"]), f"product reads {got!r}"
    for label, rows in (("product", described.get("Tags", [])),
                        ("portfolio", sc.describe_portfolio(Id=portfolio_id).get("Tags", []))):
        assert _own_tags(rows) == {"sim2real": stack_name}, f"{label} tags {rows!r}"
    linked = [p["Id"] for p in paginate(sc, "list_portfolios_for_product", "PortfolioDetails",
                                        ProductId=product_id)]
    assert linked == [portfolio_id], f"ListPortfoliosForProduct {linked!r}"
    principals = paginate(sc, "list_principals_for_portfolio", "Principals",
                          PortfolioId=portfolio_id)
    # The caller identity is the launch principal, not a check resource: the failure message
    # reports the shape of the principal list, never the ARN.
    kinds = [p["PrincipalType"] for p in principals]
    assert kinds == ["IAM"] and principals[0]["PrincipalARN"] == who, (
        f"ListPrincipalsForPortfolio holds {len(principals)} principal(s) of type {kinds!r}, "
        f"expected exactly one IAM principal naming the caller"
    )

    # Children first: an update dropping the provisioned product and both associations
    # terminates it and its nested stack while the product and portfolio still answer.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        portfolio_name, product_name, who, pp_name, greeting, url, children=False))
    status = wait_stack(cf, stack_id, timeout_s=400.0)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException", f"Provisioned product not found: {pp_id}")
    expect_error(lambda: sc.describe_provisioned_product(Id=pp_id), *gone)
    nested_after = cf.describe_stacks(StackName=out["PPStackArn"])["Stacks"][0]["StackStatus"]
    assert nested_after == "DELETE_COMPLETE", f"nested stack answers {nested_after!r}"
    left = paginate(sc, "list_portfolios_for_product", "PortfolioDetails", ProductId=product_id)
    assert left == [], f"ListPortfoliosForProduct after the update: {left!r}"
    left = paginate(sc, "list_principals_for_portfolio", "Principals", PortfolioId=portfolio_id)
    assert left == [], (
        f"ListPrincipalsForPortfolio after the update holds {len(left)} principal(s) of type "
        f"{[p['PrincipalType'] for p in left]!r}"
    )

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException",
            f"There are no local or default products with id {product_id}")
    expect_error(lambda: sc.describe_product_as_admin(Id=product_id), *gone)
    gone = ("ResourceNotFoundException",
            f"There are no local or default portfolios with id {portfolio_id}")
    expect_error(lambda: sc.describe_portfolio(Id=portfolio_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
