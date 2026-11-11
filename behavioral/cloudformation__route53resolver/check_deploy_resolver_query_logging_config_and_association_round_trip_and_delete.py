"""deploy-resolver-query-logging-config-and-association-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-query-logging-config-and-association-round-trip-and-delete"
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


# ---- Check-specific: the template, then run(). ----

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: {log_group_name}
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.95.0.0/16
      Tags:
        - Key: sim2real-vpc
          Value: {check}
  Config:
    Type: AWS::Route53Resolver::ResolverQueryLoggingConfig
    Properties:
      Name: {config_name}
      DestinationArn: !GetAtt LogGroup.Arn
  Association:
    Type: AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation
    Properties:
      ResolverQueryLogConfigId: !Ref Config
      ResourceId: !Ref Vpc
Outputs:
  ConfigId:
    Value: !Ref Config
  ConfigArn:
    Value: !GetAtt Config.Arn
  ConfigCreationTime:
    Value: !GetAtt Config.CreationTime
  AssocId:
    Value: !Ref Association
  AssocStatus:
    Value: !GetAtt Association.Status
  VpcId:
    Value: !Ref Vpc
"""

_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message: str) -> str:
    """message minus Route 53 Resolver's per-request trailing ``Trace Id: "..."`` suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


_CFG_NOT_FOUND = ("ResourceNotFoundException",
                  "[RSLVR-01601] The specified query logging configuration doesn't exist.")
_ASSOC_NOT_FOUND = ("ResourceNotFoundException",
                    "[RSLVR-01602] The specified query logging configuration association doesn't exist.")


def _resolver_refusal(fn):
    """(Error.Code, Error.Message minus the per-request Trace Id) of the ClientError fn() raises;
    a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message", ""))
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _poll(read, done, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """read() until done(value) holds; the last value either way, for the assert to grade."""
    deadline = time.monotonic() + timeout_s
    value = read()
    while not done(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = read()
    return value


def _configs_named(r53r, name: str) -> list[dict]:
    """Every query logging config named ``name``, read through every page."""
    configs = paginate(r53r, "list_resolver_query_log_configs", "ResolverQueryLogConfigs",
                       Filters=[{"Name": "Name", "Values": [name]}])
    return [c for c in configs if c["Name"] == name]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResolverQueryLoggingConfig and its VPC association deployed via CloudFormation read
    back through Route 53 Resolver's own API with the template's values, and deleting the
    stack removes both, which Resolver then reports gone by id.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_GetResolverQueryLogConfig.html
    """
    cf = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")

    stack = ctx.unique_name("sim2real-r53rqlc-stack-")
    log_group_name = ctx.unique_name("sim2real-r53rqlc-lg-")
    config_name = ctx.unique_name("sim2real-r53rqlc-cfg-")
    template = _TEMPLATE.format(log_group_name=log_group_name, config_name=config_name, check=CHECK)

    stack_id = create_stack(ctx, cf, stack, template)
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    config_id, assoc_id, vpc_id = outputs["ConfigId"], outputs["AssocId"], outputs["VpcId"]

    cfg = r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
        "ResolverQueryLogConfig"
    ]
    listed = _configs_named(r53r, config_name)
    assert [c["Id"] for c in listed] == [config_id], (
        f"expected Ref Config {config_id!r} to be the one config Resolver lists under "
        f"{config_name!r}, got {[c['Id'] for c in listed]!r}"
    )
    assert cfg["Name"] == config_name, f"expected Name {config_name!r}, Resolver reports {cfg['Name']!r}"
    assert cfg["Arn"] == outputs["ConfigArn"], (
        f"GetAtt Config.Arn {outputs['ConfigArn']!r} must equal Resolver's own Arn {cfg['Arn']!r}"
    )
    assert cfg["CreationTime"] == outputs["ConfigCreationTime"], (
        f"GetAtt Config.CreationTime {outputs['ConfigCreationTime']!r} must equal Resolver's own "
        f"CreationTime {cfg['CreationTime']!r}"
    )
    assert cfg["Status"] == "CREATED", f"expected Status CREATED, Resolver reports {cfg['Status']!r}"
    partition = stack_id.split(":")[1]
    want_destination = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{log_group_name}"
    assert cfg["DestinationArn"] == want_destination, (
        f"expected the canonical (wildcard-stripped) log-group ARN {want_destination!r}, Resolver "
        f"reports {cfg['DestinationArn']!r}"
    )

    # The association Ref against an independent read: the associations listed for the config.
    listed_assocs = [(a["Id"], a["ResourceId"]) for a in paginate(
        r53r, "list_resolver_query_log_config_associations", "ResolverQueryLogConfigAssociations",
        Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [config_id]}])]
    assert listed_assocs == [(assoc_id, vpc_id)], (
        f"Resolver lists the associations {listed_assocs!r} for {config_id!r}, expected the Ref "
        f"{assoc_id!r} on the VPC {vpc_id!r}"
    )
    assoc = r53r.get_resolver_query_log_config_association(
        ResolverQueryLogConfigAssociationId=assoc_id
    )["ResolverQueryLogConfigAssociation"]
    assert assoc["Id"] == assoc_id, f"Ref must be the association's own Id, got {assoc['Id']!r}"
    assert assoc["ResolverQueryLogConfigId"] == config_id, (
        f"expected the association to reference {config_id!r}, Resolver reports "
        f"{assoc['ResolverQueryLogConfigId']!r}"
    )
    assert assoc["ResourceId"] == vpc_id, (
        f"expected the association to reference {vpc_id!r}, Resolver reports {assoc['ResourceId']!r}"
    )
    assert assoc["Status"] == "ACTIVE" == outputs["AssocStatus"], (
        f"expected GetAtt Association.Status {outputs['AssocStatus']!r} and Resolver's own Status "
        f"{assoc['Status']!r} to both be ACTIVE"
    )

    cfg_after = _poll(
        lambda: r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
            "ResolverQueryLogConfig"
        ],
        lambda c: c["AssociationCount"] == 1,
    )
    assert cfg_after["AssociationCount"] == 1, (
        f"expected AssociationCount 1 once the stack's association is ACTIVE, got "
        f"{cfg_after['AssociationCount']!r}"
    )

    delete_stack(cf, stack_id)

    got = _resolver_refusal(lambda: r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id))
    assert got == _CFG_NOT_FOUND, f"reading the deleted config answered {got!r}, expected {_CFG_NOT_FOUND!r}"
    got = _resolver_refusal(lambda: r53r.get_resolver_query_log_config_association(
        ResolverQueryLogConfigAssociationId=assoc_id))
    assert got == _ASSOC_NOT_FOUND, (
        f"reading the deleted association answered {got!r}, expected {_ASSOC_NOT_FOUND!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
