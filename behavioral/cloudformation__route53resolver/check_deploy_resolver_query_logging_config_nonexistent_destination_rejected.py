"""deploy-resolver-query-logging-config-nonexistent-destination-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-query-logging-config-nonexistent-destination-rejected"
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

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Config:
    Type: AWS::Route53Resolver::ResolverQueryLoggingConfig
    Properties:
      Name: {config_name}
      DestinationArn: !Sub 'arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{log_group_name}'
"""

_TRACE_ID_RE = re.compile(r'Trace Id: "[0-9a-f-]+"')
_REJECTED = (
    '[RSLVR-01600] Access denied Trace Id: "<trace-id>" (Service: AmazonRoute53Resolver; '
    "Status Code: 400; Error Code: AccessDeniedException; Request ID: <id>; Proxy: null)",
    "GeneralServiceException",
)
_STACK_REASON = "The following resource(s) failed to create: [Config]. "


def _delete_log_group(logs, name):
    """Delete the log group; only its own not-found means it never existed."""
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _configs_named(r53r, name: str) -> list[dict]:
    """Every query logging config named ``name``, read through every page."""
    configs = paginate(r53r, "list_resolver_query_log_configs", "ResolverQueryLogConfigs",
                       Filters=[{"Name": "Name", "Values": [name]}])
    return [c for c in configs if c["Name"] == name]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResolverQueryLoggingConfig naming a log group that was never created fails CREATE with
    Resolver's own access-denied reason, and no config under that name is ever stored; the same
    template naming a log group that exists deploys and reads back.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverQueryLogConfig.html
    """
    cf = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")
    logs = ctx.client("logs")

    # Positive control: the same template, its DestinationArn naming a log group that exists.
    owned_log_group = ctx.unique_name("sim2real-r53rqlc-lg-")
    ctx.on_cleanup(lambda: _delete_log_group(logs, owned_log_group))
    logs.create_log_group(logGroupName=owned_log_group, tags={"sim2real": CHECK})
    good_stack = ctx.unique_name("sim2real-r53rqlc-good-stack-")
    good_name = ctx.unique_name("sim2real-r53rqlc-good-cfg-")
    good_id = create_stack(
        ctx, cf, good_stack,
        _TEMPLATE.format(config_name=good_name, log_group_name=owned_log_group),
    )
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"the control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    good_ref = cf.describe_stack_resource(StackName=good_id, LogicalResourceId="Config")[
        "StackResourceDetail"]["PhysicalResourceId"]
    good_listed = _configs_named(r53r, good_name)
    assert [c["Id"] for c in good_listed] == [good_ref], (
        f"expected the control's Ref {good_ref!r} to be the one config Resolver lists under "
        f"{good_name!r}, got {[c['Id'] for c in good_listed]!r}"
    )
    good_cfg = r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=good_ref)[
        "ResolverQueryLogConfig"]
    partition = good_id.split(":")[1]
    want_destination = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{owned_log_group}"
    got = (good_cfg["Name"], good_cfg["DestinationArn"], good_cfg["Status"])
    assert got == (good_name, want_destination, "CREATED"), (
        f"expected the control config (Name, DestinationArn, Status) "
        f"{(good_name, want_destination, 'CREATED')!r}, Resolver reports {got!r}"
    )

    stack = ctx.unique_name("sim2real-r53rqlc-bad-stack-")
    config_name = ctx.unique_name("sim2real-r53rqlc-bad-cfg-")
    absent_log_group = ctx.unique_name("sim2real-r53rqlc-absent-lg-")
    template = _TEMPLATE.format(config_name=config_name, log_group_name=absent_log_group)

    stack_id = create_stack(ctx, cf, stack, template, OnFailure="DO_NOTHING")
    status = wait_stack(cf, stack_id, timeout_s=120.0)
    assert status == "CREATE_FAILED", f"stack {stack!r} ended {status!r}, expected CREATE_FAILED"

    stack_reason = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatusReason"]
    assert stack_reason == _STACK_REASON, (
        f"expected stack status reason {_STACK_REASON!r}, got {stack_reason!r}"
    )

    message, code = handler_reason(failed_reason(stack_events(cf, stack_id), "Config"),
                                   ctx.account, config_name, absent_log_group)
    got = (_TRACE_ID_RE.sub('Trace Id: "<trace-id>"', message), code)
    assert got == _REJECTED, f"expected reason {_REJECTED!r}, got {got!r}"

    listed = _configs_named(r53r, config_name)
    assert listed == [], f"a config whose create failed must not exist in any status, got {listed!r}"

    delete_stack(cf, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
