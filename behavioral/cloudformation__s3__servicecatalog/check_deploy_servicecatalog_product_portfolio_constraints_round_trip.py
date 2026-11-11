"""deploy-servicecatalog-product-portfolio-constraints-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-product-portfolio-constraints-round-trip"
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

_LAUNCH_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "servicecatalog.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_RULES = {"Rule1": {"Assertions": [{
    "Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": "AWS::Region"}, "none"]}]},
    "AssertDescription": "the region is never the literal string none",
}]}}

#: The associations and constraints a child-dropping update removes; parents and roles stay.
_CHILDREN = ("Assoc", "LaunchRoleConstraint", "NotifyConstraint", "TemplateConstraint",
             "ResourceUpdateConstraint", "ActionAssoc")
_PARENT_OUTPUTS = ("PortfolioRef", "ProductRef", "ProductNameAtt", "ArtifactIds", "LaunchRoleArn",
                   "TopicArn", "ActionId")


def _own_tags(rows):
    """Service Catalog ``Tags`` rows as {key: value}, without the ``aws:`` system tags."""
    return {r["Key"]: r["Value"] for r in rows if not r["Key"].startswith("aws:")}


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
    body = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                 "Properties": {"Type": "String", "Value": "sim2real"}}},
    })
    s3.put_object(Bucket=bucket, Key="product.json", Body=body.encode())
    return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/product.json"


def _template(ctx, portfolio_name, product_name, role_name, topic_name, action_name, url,
              children=True):
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
            "LaunchRole": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name, "AssumeRolePolicyDocument": _LAUNCH_TRUST}},
            "LaunchRoleConstraint": {
                "Type": "AWS::ServiceCatalog::LaunchRoleConstraint", "DependsOn": "Assoc",
                "Properties": {"PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"},
                                "RoleArn": {"Fn::GetAtt": ["LaunchRole", "Arn"]}}},
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
            "NotifyConstraint": {
                "Type": "AWS::ServiceCatalog::LaunchNotificationConstraint", "DependsOn": "Assoc",
                "Properties": {"PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"},
                                "NotificationArns": [{"Ref": "Topic"}]}},
            "TemplateConstraint": {
                "Type": "AWS::ServiceCatalog::LaunchTemplateConstraint", "DependsOn": "Assoc",
                "Properties": {"PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"},
                                "Rules": json.dumps(_RULES)}},
            "ResourceUpdateConstraint": {
                "Type": "AWS::ServiceCatalog::ResourceUpdateConstraint", "DependsOn": "Assoc",
                "Properties": {"PortfolioId": {"Ref": "Portfolio"}, "ProductId": {"Ref": "Product"},
                                "TagUpdateOnProvisionedProduct": "ALLOWED"}},
            "Action": {"Type": "AWS::ServiceCatalog::ServiceAction", "Properties": {
                "Name": action_name, "DefinitionType": "SSM_AUTOMATION",
                "Definition": [
                    {"Key": "Name", "Value": "AWS-PublishSNSNotification"},
                    {"Key": "Version", "Value": "1"},
                    {"Key": "AssumeRole", "Value": {"Fn::GetAtt": ["LaunchRole", "Arn"]}},
                ]}},
            "ActionAssoc": {"Type": "AWS::ServiceCatalog::ServiceActionAssociation", "Properties": {
                "ProductId": {"Ref": "Product"},
                "ProvisioningArtifactId": {"Fn::Select": [0, {"Fn::Split": [
                    ",", {"Fn::GetAtt": "Product.ProvisioningArtifactIds"}]}]},
                "ServiceActionId": {"Fn::GetAtt": ["Action", "Id"]}}},
        },
        "Outputs": {
            "PortfolioRef": {"Value": {"Ref": "Portfolio"}},
            "ProductRef": {"Value": {"Ref": "Product"}},
            "ProductNameAtt": {"Value": {"Fn::GetAtt": ["Product", "ProductName"]}},
            "ArtifactIds": {"Value": {"Fn::GetAtt": ["Product", "ProvisioningArtifactIds"]}},
            "AssocRef": {"Value": {"Ref": "Assoc"}},
            "LaunchRoleArn": {"Value": {"Fn::GetAtt": ["LaunchRole", "Arn"]}},
            "LaunchRoleConstraintRef": {"Value": {"Ref": "LaunchRoleConstraint"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "NotifyConstraintRef": {"Value": {"Ref": "NotifyConstraint"}},
            "TemplateConstraintRef": {"Value": {"Ref": "TemplateConstraint"}},
            "ResourceUpdateConstraintRef": {"Value": {"Ref": "ResourceUpdateConstraint"}},
            "ActionId": {"Value": {"Fn::GetAtt": ["Action", "Id"]}},
            "ActionAssocRef": {"Value": {"Ref": "ActionAssoc"}},
        },
    }
    if not children:
        for key in _CHILDREN:
            del template["Resources"][key]
        template["Outputs"] = {k: template["Outputs"][k] for k in _PARENT_OUTPUTS}
    return json.dumps(template)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation product, portfolio, association, service action and four constraints read back.

    An update dropping the associations and constraints removes each while product and portfolio
    answer, and the stack delete removes the product, portfolio and service action.
    """
    cf = ctx.client("cloudformation")
    sc = ctx.client("servicecatalog")
    s3 = ctx.client("s3")

    portfolio_name = ctx.unique_name("sim2real-sc-pf-")
    product_name = ctx.unique_name("sim2real-sc-prod-")
    role_name = ctx.unique_name("sim2real-sc-launch-")
    topic_name = ctx.unique_name("sim2real-sc-topic-")
    action_name = ctx.unique_name("sim2real-sc-action-")
    stack_name = ctx.unique_name("sim2real-sc-constraints-")

    url = _host_template(ctx, s3)
    template = _template(ctx, portfolio_name, product_name, role_name, topic_name, action_name, url)
    stack_id = create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    portfolio_id, product_id = out["PortfolioRef"], out["ProductRef"]
    artifact_id = out["ArtifactIds"]

    # Ref against an independent search/list, never a read keyed by the Ref itself.
    found_products = [
        p["ProductViewSummary"] for p in
        paginate(sc, "search_products_as_admin", "ProductViewDetails",
                 Filters={"FullTextSearch": [product_name]})
        if p["ProductViewSummary"]["Name"] == product_name
    ]
    assert [p["ProductId"] for p in found_products] == [product_id], (
        f"SearchProductsAsAdmin for {product_name!r} found {found_products!r}, "
        f"expected exactly one product with Id {product_id!r}"
    )
    found_portfolios = [
        p for p in paginate(sc, "list_portfolios", "PortfolioDetails")
        if p["DisplayName"] == portfolio_name
    ]
    assert [p["Id"] for p in found_portfolios] == [portfolio_id], (
        f"ListPortfolios for {portfolio_name!r} found {found_portfolios!r}, "
        f"expected exactly one portfolio with Id {portfolio_id!r}"
    )
    assert out["ProductNameAtt"] == product_name, (
        f"GetAtt ProductName {out['ProductNameAtt']!r} != {product_name!r}"
    )
    assert found_portfolios[0]["ProviderName"] == "sim2real", f"portfolio {found_portfolios!r}"

    # Every templated property, read back through Service Catalog's own describe calls.
    described = sc.describe_product_as_admin(Id=product_id)
    admin = described["ProductViewDetail"]["ProductViewSummary"]
    product_tags = _own_tags(described.get("Tags", []))
    assert product_tags == {"sim2real": stack_name}, f"product tags {product_tags!r}"
    portfolio_tags = _own_tags(sc.describe_portfolio(Id=portfolio_id).get("Tags", []))
    assert portfolio_tags == {"sim2real": stack_name}, f"portfolio tags {portfolio_tags!r}"
    assert (admin["Name"], admin["Owner"], admin["ProductId"]) == (
        product_name, "sim2real", product_id
    ), f"DescribeProductAsAdmin returned {admin!r}"
    artifacts = sc.list_provisioning_artifacts(ProductId=product_id)["ProvisioningArtifactDetails"]
    assert [a["Id"] for a in artifacts] == [artifact_id], (
        f"ListProvisioningArtifacts returned {artifacts!r}, expected exactly {artifact_id!r}"
    )
    assert artifacts[0]["Name"] == "v1", f"artifact name {artifacts[0]['Name']!r} != 'v1'"

    portfolios_for_product = paginate(sc, "list_portfolios_for_product", "PortfolioDetails",
                                      ProductId=product_id)
    assert [p["Id"] for p in portfolios_for_product] == [portfolio_id], (
        f"ListPortfoliosForProduct returned {portfolios_for_product!r}, expected {portfolio_id!r}"
    )
    assert out["AssocRef"] == f"{portfolio_id}|{product_id}", (
        f"PortfolioProductAssociation Ref {out['AssocRef']!r} != "
        f"{portfolio_id}|{product_id}"
    )

    constraints = paginate(sc, "list_constraints_for_portfolio", "ConstraintDetails",
                           PortfolioId=portfolio_id, ProductId=product_id)
    constraint_types = {c["ConstraintId"]: c["Type"] for c in constraints}
    assert constraint_types == {
        out["LaunchRoleConstraintRef"]: "LAUNCH",
        out["NotifyConstraintRef"]: "NOTIFICATION",
        out["TemplateConstraintRef"]: "TEMPLATE",
        out["ResourceUpdateConstraintRef"]: "RESOURCE_UPDATE",
    }, f"ListConstraintsForPortfolio reports {constraint_types!r}"

    launch = sc.describe_constraint(Id=out["LaunchRoleConstraintRef"])
    assert launch["ConstraintDetail"]["Type"] == "LAUNCH", (
        f"DescribeConstraint Type {launch['ConstraintDetail']['Type']!r}, expected 'LAUNCH'"
    )
    assert json.loads(launch["ConstraintParameters"]) == {"RoleArn": out["LaunchRoleArn"]}, (
        f"LaunchRoleConstraint params {launch['ConstraintParameters']!r} != RoleArn "
        f"{out['LaunchRoleArn']!r}"
    )

    notify = sc.describe_constraint(Id=out["NotifyConstraintRef"])
    assert notify["ConstraintDetail"]["Type"] == "NOTIFICATION", (
        f"DescribeConstraint Type {notify['ConstraintDetail']['Type']!r}, expected 'NOTIFICATION'"
    )
    assert json.loads(notify["ConstraintParameters"]) == {"NotificationArns": [out["TopicArn"]]}, (
        f"LaunchNotificationConstraint params {notify['ConstraintParameters']!r} != "
        f"NotificationArns [{out['TopicArn']!r}]"
    )

    tmpl_constraint = sc.describe_constraint(Id=out["TemplateConstraintRef"])
    assert tmpl_constraint["ConstraintDetail"]["Type"] == "TEMPLATE", (
        f"DescribeConstraint Type {tmpl_constraint['ConstraintDetail']['Type']!r}, expected 'TEMPLATE'"
    )
    assert json.loads(tmpl_constraint["ConstraintParameters"]) == {"Rules": _RULES}, (
        f"LaunchTemplateConstraint params {tmpl_constraint['ConstraintParameters']!r} != "
        f"Rules {_RULES!r}"
    )

    ru_constraint = sc.describe_constraint(Id=out["ResourceUpdateConstraintRef"])
    assert ru_constraint["ConstraintDetail"]["Type"] == "RESOURCE_UPDATE", (
        f"DescribeConstraint Type {ru_constraint['ConstraintDetail']['Type']!r}, expected 'RESOURCE_UPDATE'"
    )
    assert json.loads(ru_constraint["ConstraintParameters"]) == {
        "Version": "2.0", "Properties": {"TagUpdateOnProvisionedProduct": "ALLOWED"}}, (
        f"ResourceUpdateConstraint params {ru_constraint['ConstraintParameters']!r}"
    )

    action = sc.describe_service_action(Id=out["ActionId"])["ServiceActionDetail"]
    assert action["ServiceActionSummary"]["Name"] == action_name, (
        f"ServiceAction name {action['ServiceActionSummary']['Name']!r} != {action_name!r}"
    )
    assert (action["Definition"]["Name"], action["Definition"]["AssumeRole"]) == (
        "AWS-PublishSNSNotification", out["LaunchRoleArn"]
    ), f"ServiceAction definition {action['Definition']!r}"

    action_rows = paginate(sc, "list_service_actions_for_provisioning_artifact",
                           "ServiceActionSummaries", ProductId=product_id,
                           ProvisioningArtifactId=artifact_id)
    assert [a["Id"] for a in action_rows] == [out["ActionId"]], (
        f"ListServiceActionsForProvisioningArtifact returned {action_rows!r}, "
        f"expected exactly {out['ActionId']!r}"
    )
    assert out["ActionAssocRef"] == f"{product_id}|{artifact_id}|{out['ActionId']}", (
        f"ServiceActionAssociation Ref {out['ActionAssocRef']!r} != "
        f"{product_id}|{artifact_id}|{out['ActionId']}"
    )

    # Children first: an update dropping the associations and constraints removes each while
    # the product and portfolio still answer.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(
        ctx, portfolio_name, product_name, role_name, topic_name, action_name, url,
        children=False), Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    for ref in ("LaunchRoleConstraintRef", "NotifyConstraintRef", "TemplateConstraintRef",
                "ResourceUpdateConstraintRef"):
        gone = ("ResourceNotFoundException", f"Constraint {out[ref]} not found.")
        expect_error(lambda ref=ref: sc.describe_constraint(Id=out[ref]), *gone)
    left = paginate(sc, "list_portfolios_for_product", "PortfolioDetails", ProductId=product_id)
    assert left == [], f"ListPortfoliosForProduct after the update: {left!r}"
    left = paginate(sc, "list_service_actions_for_provisioning_artifact", "ServiceActionSummaries",
                    ProductId=product_id, ProvisioningArtifactId=artifact_id)
    assert left == [], f"ListServiceActionsForProvisioningArtifact after the update: {left!r}"
    survived = sc.describe_portfolio(Id=portfolio_id)["PortfolioDetail"]["Id"]
    assert survived == portfolio_id, (
        f"DescribePortfolio after the update reads Id {survived!r}, expected {portfolio_id!r}"
    )
    assert sc.describe_service_action(Id=out["ActionId"])["ServiceActionDetail"][
        "ServiceActionSummary"]["Name"] == action_name, "the service action did not survive"

    delete_stack(cf, stack_id)
    gone = ("ResourceNotFoundException",
            f"There are no local or default products with id {product_id}")
    expect_error(lambda: sc.describe_product_as_admin(Id=product_id), *gone)
    gone = ("ResourceNotFoundException", f"Product {product_id} not found.")
    expect_error(lambda: sc.list_provisioning_artifacts(ProductId=product_id), *gone)
    gone = ("ResourceNotFoundException",
            f"There are no local or default portfolios with id {portfolio_id}")
    expect_error(lambda: sc.describe_portfolio(Id=portfolio_id), *gone)
    gone = ("ResourceNotFoundException", f"Service action {out['ActionId']} not found")
    expect_error(lambda: sc.describe_service_action(Id=out["ActionId"]), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
