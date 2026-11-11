"""deploy-cfn-cases-domain-name-conflict-rolls-back-stack."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-cases-domain-name-conflict-rolls-back-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "connectcases"]

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

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A single Cases domain.
Parameters:
  DomainName: {Type: String}
Resources:
  Domain:
    Type: AWS::Cases::Domain
    Properties:
      Name: !Ref DomainName
Outputs:
  DomainId: {Value: !GetAtt Domain.DomainId}
"""

# The handler reason with only the request id, attempt count and account masked.
_CONFLICT = (
    "Domain name already exists for account: <account> (Service: ConnectCases, Status Code: 409, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "AlreadyExists",
)


def _all_domains(cc) -> list[dict]:
    """Every page of ListDomains; the account can hold more domains than one page."""
    out, token = [], None
    while True:
        page = cc.list_domains(**({"nextToken": token} if token else {}))
        out.extend(page.get("domains", []))
        token = page.get("nextToken")
        if not token:
            return out


def _delete_domains_named(cc, name: str) -> None:
    """Delete every domain ListDomains shows under the run's unique ``name``."""
    for domain in _all_domains(cc):
        if domain["name"] == name:
            cc.delete_domain(domainId=domain["domainId"])


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack that names a Cases domain already used by another domain fails
    with the exact ConnectCases conflict message and rolls back, leaving the original domain
    untouched; a stack naming a fresh, distinct domain still succeeds.
    """
    cc = ctx.client("connectcases")
    cfn = ctx.client("cloudformation")

    conflict_name = ctx.unique_name("sim2real-cfn-cases-conflict-")
    # Cleanup first, by the run's unique name: a domain AWS accepted is deleted even if the call
    # raises.
    ctx.on_cleanup(lambda: _delete_domains_named(cc, conflict_name))
    original = cc.create_domain(name=conflict_name)
    original_domain_id = original["domainId"]
    cc.tag_resource(arn=original["domainArn"], tags={"sim2real": conflict_name})

    stack_name = ctx.unique_name("sim2real-cfn-cases-conflict-stack-")
    stack_id = create_stack(
        ctx, cfn, stack_name, _TEMPLATE,
        Parameters=[{"ParameterKey": "DomainName", "ParameterValue": conflict_name}],
    )
    final_status = wait_stack(cfn, stack_id)
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected the conflicting stack to roll back, got {final_status!r}"
    )

    reason = failed_reason(stack_events(cfn, stack_id), "Domain")
    got_reason = handler_reason(reason, ctx.account)
    assert got_reason == _CONFLICT, (
        f"expected the Domain CREATE_FAILED reason {_CONFLICT!r}, got {got_reason!r}"
    )

    surviving = cc.get_domain(domainId=original_domain_id)
    assert surviving["name"] == conflict_name, (
        f"expected the original domain to keep its name {conflict_name!r}, got {surviving['name']!r}"
    )
    assert surviving["domainStatus"] == "Active", (
        f"expected the original domain to remain Active, got {surviving['domainStatus']!r}"
    )
    matching = [d for d in _all_domains(cc) if d["name"] == conflict_name]
    assert len(matching) == 1, f"expected exactly one domain named {conflict_name!r}, got {matching!r}"
    assert matching[0]["domainId"] == original_domain_id, (
        f"expected the surviving domain to be {original_domain_id!r}, got {matching[0]['domainId']!r}"
    )

    # Positive control: a fresh, distinct name still deploys cleanly through the same stack shape.
    distinct_name = ctx.unique_name("sim2real-cfn-cases-control-")
    control_stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-cfn-cases-control-stack-"), _TEMPLATE,
        Parameters=[{"ParameterKey": "DomainName", "ParameterValue": distinct_name}],
    )
    status = wait_stack(cfn, control_stack_id)
    assert status == "CREATE_COMPLETE", f"expected the control stack CREATE_COMPLETE, got {status!r}"
    control_domain_id = stack_outputs(cfn, control_stack_id)["DomainId"]
    control_domain = cc.get_domain(domainId=control_domain_id)
    assert control_domain["name"] == distinct_name, (
        f"expected the control domain's name to be {distinct_name!r}, got {control_domain['name']!r}"
    )
    assert control_domain["domainStatus"] == "Active", (
        f"expected the control domain to be Active, got {control_domain['domainStatus']!r}"
    )
    delete_stack(cfn, control_stack_id)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
