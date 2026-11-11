"""deploy-config-account-scoped-resources-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-config-account-scoped-resources-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "config"]

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

_AGGREGATOR_NOT_FOUND = (
    "NoSuchConfigurationAggregatorException",
    "The configuration aggregator does not exist. Check the configuration aggregator name "
    "and try again.",
)
_TEMPLATE_TAGS = {"sim2real-check": CHECK}
_QUERY_EXPRESSION = "SELECT resourceId, resourceType WHERE resourceType = 'AWS::CloudFormation::Stack'"
_QUERY_DESCRIPTION = "sim2real probe query"


def _template(aggregator_name: str, query_name: str) -> str:
    tags_list = [{"Key": k, "Value": v} for k, v in _TEMPLATE_TAGS.items()]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AggAuth": {
                "Type": "AWS::Config::AggregationAuthorization",
                "Properties": {
                    "AuthorizedAccountId": {"Ref": "AWS::AccountId"},
                    "AuthorizedAwsRegion": {"Ref": "AWS::Region"},
                    "Tags": tags_list,
                },
            },
            "Aggregator": {
                "Type": "AWS::Config::ConfigurationAggregator",
                "Properties": {
                    "ConfigurationAggregatorName": aggregator_name,
                    "AccountAggregationSources": [{
                        "AccountIds": [{"Ref": "AWS::AccountId"}],
                        "AwsRegions": [{"Ref": "AWS::Region"}],
                        "AllAwsRegions": False,
                    }],
                    "Tags": tags_list,
                },
            },
            "Query": {
                "Type": "AWS::Config::StoredQuery",
                "Properties": {
                    "QueryName": query_name,
                    "QueryDescription": _QUERY_DESCRIPTION,
                    "QueryExpression": _QUERY_EXPRESSION,
                    "Tags": tags_list,
                },
            },
        },
        "Outputs": {
            "AggAuthRef": {"Value": {"Ref": "AggAuth"}},
            "AggAuthArn": {"Value": {"Fn::GetAtt": ["AggAuth", "AggregationAuthorizationArn"]}},
            "AggregatorRef": {"Value": {"Ref": "Aggregator"}},
            "AggregatorArn": {"Value": {"Fn::GetAtt": ["Aggregator", "ConfigurationAggregatorArn"]}},
            "QueryRef": {"Value": {"Ref": "Query"}},
            "QueryId": {"Value": {"Fn::GetAtt": ["Query", "QueryId"]}},
            "QueryArn": {"Value": {"Fn::GetAtt": ["Query", "QueryArn"]}},
        },
    })


def _user_tags(tag_list: list[dict], stack: str) -> dict:
    """The non-``aws:`` tags; the propagated stack tag, when present, must name the stack."""
    user = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    assert user.pop("sim2real", stack) == stack, f"stack tag on the resource: {tag_list!r}"
    return user


def _own_authorizations(config, account: str, region: str) -> list[dict]:
    """Every aggregation authorization naming ``account`` and ``region``, across all pages."""
    return [
        a for page in config.get_paginator("describe_aggregation_authorizations").paginate()
        for a in page["AggregationAuthorizations"]
        if a["AuthorizedAccountId"] == account and a["AuthorizedAwsRegion"] == region
    ]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control",
      "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """Three account-scoped AWS::Config resources deployed via CloudFormation are real: Ref and
    GetAtt match Config's own values, the properties the template set read back, and deleting the
    stack removes each resource from Config's own API.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-aggregationauthorization.html
    """
    cfn = ctx.client("cloudformation")
    config = ctx.client("config")

    stack = ctx.unique_name("sim2real-cfgscope-stack-")
    aggregator_name = ctx.unique_name("sim2real-cfgscope-agg-")
    query_name = ctx.unique_name("sim2real-cfgscope-query-")

    # The authorization for this account and region is one per account: a prior one is a
    # precondition failure, never something this check overwrites or deletes.
    prior = _own_authorizations(config, ctx.account, ctx.region)
    assert prior == [], (
        f"precondition: expected no aggregation authorization for this account and region, "
        f"found {len(prior)}"
    )

    stack_id = create_stack(ctx, cfn, stack, _template(aggregator_name, query_name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)

    # AggregationAuthorization has a two-part primary identifier, so Ref returns the two key
    # properties joined by '|' rather than a minted id.
    expected_agg_auth_ref = f"{ctx.account}|{ctx.region}"
    assert outputs["AggAuthRef"] == expected_agg_auth_ref, (
        f"expected AggAuth Ref {expected_agg_auth_ref!r}, got {outputs['AggAuthRef']!r}"
    )
    assert outputs["AggregatorRef"] == aggregator_name, (
        f"expected Aggregator Ref {aggregator_name!r}, got {outputs['AggregatorRef']!r}"
    )
    assert outputs["QueryRef"] == query_name, (
        f"expected Query Ref {query_name!r}, got {outputs['QueryRef']!r}"
    )

    auths = _own_authorizations(config, ctx.account, ctx.region)
    assert [a["AggregationAuthorizationArn"] for a in auths] == [outputs["AggAuthArn"]], (
        f"expected exactly the stack's aggregation authorization for this account and region, "
        f"got {len(auths)} with ARNs matching: "
        f"{[a['AggregationAuthorizationArn'] == outputs['AggAuthArn'] for a in auths]!r}"
    )
    auth_tags = config.list_tags_for_resource(ResourceArn=outputs["AggAuthArn"])["Tags"]
    assert _user_tags(auth_tags, stack) == _TEMPLATE_TAGS, (
        f"expected the template's Tags on the aggregation authorization, got {auth_tags!r}"
    )

    aggregators = config.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[aggregator_name]
    )["ConfigurationAggregators"]
    assert len(aggregators) == 1, (
        f"expected exactly one aggregator named {aggregator_name!r}, got {len(aggregators)}"
    )
    aggregator = aggregators[0]
    assert aggregator["ConfigurationAggregatorArn"] == outputs["AggregatorArn"], (
        f"expected aggregator ARN {outputs['AggregatorArn']!r}, got "
        f"{aggregator['ConfigurationAggregatorArn']!r}"
    )
    sources = aggregator["AccountAggregationSources"]
    assert len(sources) == 1, f"expected one AccountAggregationSource, got {sources!r}"
    assert sources[0]["AccountIds"] == [ctx.account], (
        f"expected the aggregator to source this account only, got {len(sources[0]['AccountIds'])} "
        f"account id(s)"
    )
    assert sources[0]["AwsRegions"] == [ctx.region], (
        f"expected AwsRegions [{ctx.region!r}], got {sources[0]['AwsRegions']!r}"
    )
    assert sources[0].get("AllAwsRegions") is False, (
        f"expected AllAwsRegions False, got {sources[0].get('AllAwsRegions')!r}"
    )
    aggregator_tags = config.list_tags_for_resource(ResourceArn=outputs["AggregatorArn"])["Tags"]
    assert _user_tags(aggregator_tags, stack) == _TEMPLATE_TAGS, (
        f"expected the template's Tags on the aggregator, got {aggregator_tags!r}"
    )

    query = config.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert query["QueryId"] == outputs["QueryId"], (
        f"expected QueryId {outputs['QueryId']!r}, got {query['QueryId']!r}"
    )
    assert query["QueryArn"] == outputs["QueryArn"], (
        f"expected QueryArn {outputs['QueryArn']!r}, got {query['QueryArn']!r}"
    )
    assert query["Description"] == _QUERY_DESCRIPTION, (
        f"expected Description {_QUERY_DESCRIPTION!r}, got {query['Description']!r}"
    )
    assert query["Expression"] == _QUERY_EXPRESSION, (
        f"expected Expression {_QUERY_EXPRESSION!r}, got {query['Expression']!r}"
    )
    query_tags = config.list_tags_for_resource(ResourceArn=outputs["QueryArn"])["Tags"]
    assert _user_tags(query_tags, stack) == _TEMPLATE_TAGS, (
        f"expected the template's Tags on the stored query, got {query_tags!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    remaining_auths = _own_authorizations(config, ctx.account, ctx.region)
    assert remaining_auths == [], (
        f"expected no aggregation authorization for this account and region after the stack "
        f"delete, found {len(remaining_auths)}"
    )

    expect_error(
        lambda: config.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[aggregator_name]),
        *_AGGREGATOR_NOT_FOUND,
    )
    query_gone = (
        "ResourceNotFoundException",
        f"The query '{query_name}' provided in the request is invalid. Please check the query "
        "name.",
    )
    expect_error(lambda: config.get_stored_query(QueryName=query_name), *query_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
