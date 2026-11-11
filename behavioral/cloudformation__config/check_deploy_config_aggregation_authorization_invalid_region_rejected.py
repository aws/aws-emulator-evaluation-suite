"""deploy-config-aggregation-authorization-invalid-region-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-config-aggregation-authorization-invalid-region-rejected"
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


# ---- Check-specific: the template, then run(). ----

_TEMPLATE_TAGS = {"sim2real-check": CHECK}
# The handler message with the run's unsupported region masked as <name>.
_REJECTED = (
    "Invalid request provided: Your request contains unsupported region '<name>'. Specify a "
    "region where AWS Config aggregation is supported. (Service: Config, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(region_value) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AggAuth": {
                "Type": "AWS::Config::AggregationAuthorization",
                "Properties": {
                    "AuthorizedAccountId": {"Ref": "AWS::AccountId"},
                    "AuthorizedAwsRegion": region_value,
                    "Tags": [{"Key": k, "Value": v} for k, v in _TEMPLATE_TAGS.items()],
                },
            },
        },
        "Outputs": {
            "AggAuthRef": {"Value": {"Ref": "AggAuth"}},
            "AggAuthArn": {"Value": {"Fn::GetAtt": ["AggAuth", "AggregationAuthorizationArn"]}},
        },
    })


def _account_authorizations(config, account: str) -> dict[str, str]:
    """AggregationAuthorizationArn -> AuthorizedAwsRegion for every authorization naming
    ``account``, across all pages."""
    return {
        a["AggregationAuthorizationArn"]: a["AuthorizedAwsRegion"]
        for page in config.get_paginator("describe_aggregation_authorizations").paginate()
        for a in page["AggregationAuthorizations"]
        if a["AuthorizedAccountId"] == account
    }


def _user_tags(tag_list: list[dict], stack: str) -> dict:
    """The non-``aws:`` tags; the propagated stack tag, when present, must name the stack."""
    user = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    assert user.pop("sim2real", stack) == stack, f"stack tag on the resource: {tag_list!r}"
    return user


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """A CloudFormation AWS::Config::AggregationAuthorization naming a region AWS Config does not
    support for aggregation rolls the stack back with HandlerErrorCode InvalidRequest, while the
    same resource type with a valid region still deploys, reads back and deletes cleanly.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-aggregationauthorization.html
    """
    cfn = ctx.client("cloudformation")
    config = ctx.client("config")

    # The authorization for this account and region is one per account: a prior one is a
    # precondition failure, never something this check overwrites or deletes.
    before = _account_authorizations(config, ctx.account)
    assert ctx.region not in before.values(), (
        "precondition: an aggregation authorization for this account and region already exists"
    )

    # Positive control: the same template with only AuthorizedAwsRegion valid.
    good_stack = ctx.unique_name("sim2real-cfgagginv-good-stack-")
    good_stack_id = create_stack(ctx, cfn, good_stack, _template({"Ref": "AWS::Region"}))
    good_status = wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"positive control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_outputs = stack_outputs(cfn, good_stack_id)
    expected_ref = f"{ctx.account}|{ctx.region}"
    assert good_outputs["AggAuthRef"] == expected_ref, (
        f"expected the control's Ref to be '<account>|{ctx.region}', got "
        f"{good_outputs['AggAuthRef'].split('|')[-1]!r} as its region part"
    )
    good_arn = good_outputs["AggAuthArn"]
    after_good = _account_authorizations(config, ctx.account)
    assert set(after_good) - set(before) == {good_arn}, (
        f"expected the control to add exactly its own authorization, added "
        f"{len(set(after_good) - set(before))} (its own included: {good_arn in after_good!r})"
    )
    assert after_good[good_arn] == ctx.region, (
        f"expected AuthorizedAwsRegion {ctx.region!r}, got {after_good[good_arn]!r}"
    )
    good_tags = config.list_tags_for_resource(ResourceArn=good_arn)["Tags"]
    assert _user_tags(good_tags, good_stack) == _TEMPLATE_TAGS, (
        f"expected the template's Tags on the control authorization, got {good_tags!r}"
    )

    # Negative: only AuthorizedAwsRegion changes, to a syntactically valid but unsupported region
    # name. CloudFormation's own schema has no region enum for this property, so the request
    # reaches Config, which rejects it.
    bad_region = ctx.unique_name("sim2real-not-a-region-").lower()
    bad_stack = ctx.unique_name("sim2real-cfgagginv-bad-stack-")
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template(bad_region))
    bad_status = wait_stack(cfn, bad_stack_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} with an unsupported region ended {bad_status!r}, expected "
        f"ROLLBACK_COMPLETE"
    )
    reason = failed_reason(stack_events(cfn, bad_stack_id), "AggAuth")
    got = handler_reason(reason, ctx.account, bad_region)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Before any delete: the rolled-back resource keeps the composite <account>|<region> id it
    # was requested under, and Config lists no authorization beyond the control's.
    bad_resources = cfn.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    physical = [r.get("PhysicalResourceId", "") for r in bad_resources if r["LogicalResourceId"] == "AggAuth"]
    assert physical == [f"{ctx.account}|{bad_region}"], (
        f"expected the rejected AggAuth's PhysicalResourceId '<account>|{bad_region}', got "
        f"{[p.replace(ctx.account, '<account>') for p in physical]!r}"
    )
    after_bad = _account_authorizations(config, ctx.account)
    assert after_bad == after_good, (
        f"the rejected stack changed this account's aggregation authorizations: added regions "
        f"{sorted(set(after_bad.values()) - set(after_good.values()))!r}"
    )

    # The control deletes cleanly through Config's own API.
    delete_stack(cfn, good_stack_id)
    after_delete = _account_authorizations(config, ctx.account)
    assert after_delete == before, (
        "after the control's stack delete this account's aggregation authorizations differ "
        f"from before the check: control still listed {good_arn in after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
