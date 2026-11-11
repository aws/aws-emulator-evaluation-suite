"""deploy-servicecatalog-portfolio-tagoption-and-serviceaction-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-servicecatalog-portfolio-tagoption-and-serviceaction-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "servicecatalog"]

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

def _template(display_name: str, provider_name: str, description: str,
           tag_key: str, tag_value: str, action_name: str, associations=True) -> str:
    resources = {
        "PrincipalRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                        "Action": "sts:AssumeRole",
                    }],
                },
            },
        },
        "Portfolio": {
            "Type": "AWS::ServiceCatalog::Portfolio",
            "Properties": {
                "DisplayName": display_name,
                "ProviderName": provider_name,
                "Description": description,
            },
        },
        "TagOption": {
            "Type": "AWS::ServiceCatalog::TagOption",
            "Properties": {"Key": tag_key, "Value": tag_value, "Active": True},
        },
        "PrincipalAssociation": {
            "Type": "AWS::ServiceCatalog::PortfolioPrincipalAssociation",
            "Properties": {
                "PortfolioId": {"Ref": "Portfolio"},
                "PrincipalARN": {"Fn::GetAtt": ["PrincipalRole", "Arn"]},
                "PrincipalType": "IAM",
            },
        },
        "TagOptionAssociation": {
            "Type": "AWS::ServiceCatalog::TagOptionAssociation",
            "Properties": {
                "TagOptionId": {"Ref": "TagOption"},
                "ResourceId": {"Ref": "Portfolio"},
            },
        },
        "ServiceAction": {
            "Type": "AWS::ServiceCatalog::ServiceAction",
            "Properties": {
                "Name": action_name,
                "DefinitionType": "SSM_AUTOMATION",
                "Definition": [
                    {"Key": "Name", "Value": "AWS-RestartEC2Instance"},
                    {"Key": "Version", "Value": "1"},
                ],
            },
        },
    }
    outputs = {
        "RoleArn": {"Value": {"Fn::GetAtt": ["PrincipalRole", "Arn"]}},
        "PortfolioId": {"Value": {"Ref": "Portfolio"}},
        "PortfolioNameAttr": {"Value": {"Fn::GetAtt": ["Portfolio", "PortfolioName"]}},
        "TagOptionId": {"Value": {"Ref": "TagOption"}},
        "ServiceActionId": {"Value": {"Ref": "ServiceAction"}},
        "PrincipalAssociationRef": {"Value": {"Ref": "PrincipalAssociation"}},
        "TagOptionAssociationRef": {"Value": {"Ref": "TagOptionAssociation"}},
    }
    if not associations:
        for key in ("PrincipalAssociation", "TagOptionAssociation"):
            del resources[key]
            del outputs[f"{key}Ref"]
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack's Portfolio, TagOption, PortfolioPrincipalAssociation,
    TagOptionAssociation and ServiceAction are real in Service Catalog: each Ref is the id it
    lists, every property reads back, an update drops both associations, and the delete the rest.
    """
    cfn = ctx.client("cloudformation")
    sc = ctx.client("servicecatalog")

    display_name = ctx.unique_name("sim2real-behav-scportfolio-")
    provider_name = ctx.unique_name("sim2real-behav-scprovider-")
    description = ctx.unique_name("sim2real-behav-scdesc-")
    tag_key = ctx.unique_name("sim2real-behav-sctagkey-")
    tag_value = ctx.unique_name("sim2real-behav-sctagval-")
    action_name = ctx.unique_name("sim2real-behav-scaction-")
    names = (display_name, provider_name, description, tag_key, tag_value, action_name)

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sccombo-"),
                            _template(*names), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    role_arn = outputs["RoleArn"]
    portfolio_id = outputs["PortfolioId"]
    tag_option_id = outputs["TagOptionId"]
    service_action_id = outputs["ServiceActionId"]

    # ---- Portfolio: Ref == the Id ListPortfolios gives the declared name; properties read back.
    listed = [d["Id"] for d in paginate(sc, "list_portfolios", "PortfolioDetails")
              if d["DisplayName"] == display_name]
    assert listed == [portfolio_id], f"ListPortfolios {listed!r} for Ref {portfolio_id!r}"
    portfolio = sc.describe_portfolio(Id=portfolio_id)["PortfolioDetail"]
    got = (portfolio.get("DisplayName"), portfolio.get("ProviderName"),
           portfolio.get("Description"), outputs["PortfolioNameAttr"])
    want = (display_name, provider_name, description, display_name)
    assert got == want, f"portfolio (DisplayName, Provider, Description, GetAtt) {got!r} != {want!r}"

    # ---- TagOption: Ref == the Id listed for the declared key; properties read back.
    listed = [t["Id"] for t in paginate(sc, "list_tag_options", "TagOptionDetails",
                                        Filters={"Key": tag_key})]
    assert listed == [tag_option_id], f"ListTagOptions {listed!r} for Ref {tag_option_id!r}"
    tag_option = sc.describe_tag_option(Id=tag_option_id)["TagOptionDetail"]
    got = (tag_option.get("Key"), tag_option.get("Value"), tag_option.get("Active"))
    assert got == (tag_key, tag_value, True), f"tag option reads {got!r}"

    # ---- ServiceAction: Ref == the Id listed for the declared name; Definition reads back.
    listed = [a["Id"] for a in paginate(sc, "list_service_actions", "ServiceActionSummaries")
              if a["Name"] == action_name]
    assert listed == [service_action_id], (
        f"ListServiceActions {listed!r} for Ref {service_action_id!r}"
    )
    detail = sc.describe_service_action(Id=service_action_id)["ServiceActionDetail"]
    got = (detail["ServiceActionSummary"].get("Name"),
           detail["ServiceActionSummary"].get("DefinitionType"), detail.get("Definition"))
    # The Definition reads back with the untemplated AssumeRole (null) and Parameters ("[]").
    want = (action_name, "SSM_AUTOMATION", {"AssumeRole": None, "Name": "AWS-RestartEC2Instance",
                                            "Parameters": "[]", "Version": "1"})
    assert got == want, f"service action reads {got!r}, expected {want!r}"

    # ---- The associations: Ref is "<parent>|<attached>", and each attachment reads back.
    got = (outputs["PrincipalAssociationRef"], outputs["TagOptionAssociationRef"])
    want = (f"{portfolio_id}|{role_arn}", f"{tag_option_id}|{portfolio_id}")
    assert got == want, f"association Refs {got!r}, expected {want!r}"
    principals = [(p["PrincipalARN"], p["PrincipalType"]) for p in paginate(
        sc, "list_principals_for_portfolio", "Principals", PortfolioId=portfolio_id)]
    assert principals == [(role_arn, "IAM")], f"portfolio principals {principals!r}"
    resources = [r["Id"] for r in paginate(
        sc, "list_resources_for_tag_option", "ResourceDetails", TagOptionId=tag_option_id)]
    assert resources == [portfolio_id], f"tag option resources {resources!r}"

    # ---- Children first: an update dropping both associations empties each attachment list
    # while the portfolio and the tag option still answer.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, associations=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-dropping update ended {status!r}"
    got = (
        paginate(sc, "list_principals_for_portfolio", "Principals", PortfolioId=portfolio_id),
        paginate(sc, "list_resources_for_tag_option", "ResourceDetails",
                 TagOptionId=tag_option_id),
    )
    assert got == ([], []), f"after dropping the associations: (principals, resources) {got!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException",
            f"There are no local or default portfolios with id {portfolio_id}")
    expect_error(lambda: sc.describe_portfolio(Id=portfolio_id), *gone)
    gone = ("ResourceNotFoundException", f"TagOption with ID {tag_option_id} not found")
    expect_error(lambda: sc.describe_tag_option(Id=tag_option_id), *gone)
    gone = ("ResourceNotFoundException", f"Service action {service_action_id} not found")
    expect_error(lambda: sc.describe_service_action(Id=service_action_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
