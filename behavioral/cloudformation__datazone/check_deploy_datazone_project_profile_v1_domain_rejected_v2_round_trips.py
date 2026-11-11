"""deploy-datazone-project-profile-v1-domain-rejected-v2-round-trips."""
from __future__ import annotations

import datetime
import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-datazone-project-profile-v1-domain-rejected-v2-round-trips"
GROUP = "deploy"
SERVICES = ["cloudformation", "datazone"]

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

_REJECTED = (
    "API not supported for domain version (Service: DataZone, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_PROPAGATION = re.compile(
    r"^Unable to assume role '[^']+' \(Service: DataZone, Status Code: 403, Request ID: <id>\) "
    r"\(SDK Attempt Count: <n>\)$"
)
_CFN_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)Z")
_SSO_DISABLED = {"Type": "DISABLED"}


def _parse_cfn_timestamp(value):
    """CFN's GetAtt timestamp (nanosecond ISO8601) truncated to microseconds, as tz-aware UTC."""
    m = _CFN_TS_RE.fullmatch(value)
    assert m, f"timestamp {value!r} is not in the expected CloudFormation ISO8601 form"
    micros = m.group(2)[:6].ljust(6, "0")
    return datetime.datetime.fromisoformat(f"{m.group(1)}.{micros}+00:00")


def _trust():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "datazone.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
            "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
        }],
    }


def _role():
    return {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": _trust()}}


def _create_retrying_propagation(ctx, cfn, prefix, make_template, domains, attempts=3):
    """Create a stack from ``make_template(stack_name)``; return ``(stack_name, stack_id)``.

    Only DataZone's documented AssumeRole failure on a just-created role is retried, in a new stack.
    """
    for attempt in range(1, attempts + 1):
        name = ctx.unique_name(prefix)
        stack_id = create_stack(ctx, cfn, name, json.dumps(make_template(name)),
                                Capabilities=["CAPABILITY_IAM"])
        status = wait_stack(cfn, stack_id)
        if status == "CREATE_COMPLETE":
            return name, stack_id
        events = stack_events(cfn, stack_id)
        reasons = [handler_reason(e.get("ResourceStatusReason"), ctx.account) for e in events
                   if e["LogicalResourceId"] in domains and e["ResourceStatus"] == "CREATE_FAILED"]
        retryable = bool(reasons) and all(
            code == "NotFound" and _PROPAGATION.match(msg) for msg, code in reasons
        )
        assert retryable and attempt < attempts, (
            f"stack {name!r} ended {status!r} on attempt {attempt}: {reasons!r}"
        )
        delete_stack(cfn, stack_id)
    raise AssertionError("unreachable")


def _check_domain(dz, name, domain_id, exec_role_arn, stack_name, **extra):
    """The domain by its templated name: listed once with the Ref id, every property and tag."""
    listed = [d["id"] for d in paginate(dz, "list_domains", "items") if d["name"] == name]
    assert listed == [domain_id], f"ListDomains for {name!r} found {listed!r}, Ref {domain_id!r}"
    domain = dz.get_domain(identifier=domain_id)
    got = {"name": domain["name"], "domainExecutionRole": domain["domainExecutionRole"],
           "sso": domain["singleSignOn"]["type"], "status": domain["status"]}
    got.update({k: domain.get(k) for k in extra})
    want = {"name": name, "domainExecutionRole": exec_role_arn, "sso": "DISABLED",
            "status": "AVAILABLE", **extra}
    assert got == want, f"GetDomain reads {got!r}, expected {want!r}"
    tags_ = {k: v for k, v in domain.get("tags", {}).items() if not k.startswith("aws:")}
    assert tags_ == {"sim2real": stack_name, "sim2real-dz": name}, f"domain tags {tags_!r}"


def _template(v1_name, v2_name, profile=None):
    """A V1 and a V2 domain; with ``profile=(logical id, domain logical id, name)`` a profile too."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRoleV1": _role(), "ExecRoleV2": _role(), "SvcRoleV2": _role(),
            "DomainV1": {"Type": "AWS::DataZone::Domain", "Properties": {
                "Name": v1_name,
                "DomainExecutionRole": {"Fn::GetAtt": ["ExecRoleV1", "Arn"]},
                "SingleSignOn": _SSO_DISABLED,
                "Tags": [{"Key": "sim2real-dz", "Value": v1_name}],
            }},
            "DomainV2": {"Type": "AWS::DataZone::Domain", "Properties": {
                "Name": v2_name,
                "DomainExecutionRole": {"Fn::GetAtt": ["ExecRoleV2", "Arn"]},
                "ServiceRole": {"Fn::GetAtt": ["SvcRoleV2", "Arn"]},
                "DomainVersion": "V2",
                "SingleSignOn": _SSO_DISABLED,
                "Tags": [{"Key": "sim2real-dz", "Value": v2_name}],
            }},
        },
        "Outputs": {
            "DomainV1Id": {"Value": {"Ref": "DomainV1"}},
            "DomainV2Id": {"Value": {"Ref": "DomainV2"}},
            "ExecRoleV1Arn": {"Value": {"Fn::GetAtt": ["ExecRoleV1", "Arn"]}},
            "ExecRoleV2Arn": {"Value": {"Fn::GetAtt": ["ExecRoleV2", "Arn"]}},
            "SvcRoleV2Arn": {"Value": {"Fn::GetAtt": ["SvcRoleV2", "Arn"]}},
        },
    }
    if profile is not None:
        logical_id, domain, name = profile
        template["Resources"][logical_id] = {"Type": "AWS::DataZone::ProjectProfile",
                                             "Properties": {"DomainIdentifier": {"Ref": domain},
                                                            "Name": name}}
        template["Outputs"].update({
            "ProfileRef": {"Value": {"Ref": logical_id}},
            "ProfileId": {"Value": {"Fn::GetAtt": [logical_id, "Id"]}},
            "ProfileCreatedAt": {"Value": {"Fn::GetAtt": [logical_id, "CreatedAt"]}},
        })
    return template


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataZone ProjectProfile on a V1 domain fails with DataZone's domain-version
    refusal, while the same resource on a V2 domain deploys and reads back through DataZone.
    """
    cfn = ctx.client("cloudformation")
    dz = ctx.client("datazone")
    pos_name = ctx.unique_name("sim2real-dzprojprofile-")
    neg_name = ctx.unique_name("sim2real-dzprojprofileneg-")

    stack, stack_id = _create_retrying_propagation(
        ctx, cfn, "sim2real-dzprojprofile-",
        lambda name: _template(f"{name}-v1", f"{name}-v2"), ("DomainV1", "DomainV2"))
    out = stack_outputs(cfn, stack_id)
    v1_name, v2_name = f"{stack}-v1", f"{stack}-v2"
    domain_v1, domain_v2 = out["DomainV1Id"], out["DomainV2Id"]
    _check_domain(dz, v1_name, domain_v1, out["ExecRoleV1Arn"], stack)
    _check_domain(dz, v2_name, domain_v2, out["ExecRoleV2Arn"], stack, domainVersion="V2",
                  serviceRole=out["SvcRoleV2Arn"])

    # The rejected update: a ProjectProfile whose DomainIdentifier names the V1 domain.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"], TemplateBody=json.dumps(
        _template(v1_name, v2_name, ("Profile", "DomainV1", neg_name))))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rejected update ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, stack_id), "Profile"), ctx.account)
    assert got == _REJECTED, f"Profile reason {got!r}, expected {_REJECTED!r}"

    # Positive control: the same template with DomainIdentifier naming the V2 domain.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"], TemplateBody=json.dumps(
        _template(v1_name, v2_name, ("Profile", "DomainV2", pos_name))))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"control update ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    profile_id = out["ProfileId"]
    listed = [p["id"] for p in paginate(dz, "list_project_profiles", "items",
                                        domainIdentifier=domain_v2) if p["name"] == pos_name]
    assert listed == [profile_id], f"ListProjectProfiles for {pos_name!r} found {listed!r}"
    assert out["ProfileRef"] == f"{domain_v2}|{profile_id}", f"Ref {out['ProfileRef']!r}"
    profile = dz.get_project_profile(domainIdentifier=domain_v2, identifier=profile_id)
    got = (profile["name"], profile["domainId"], profile["createdAt"])
    want = (pos_name, domain_v2, _parse_cfn_timestamp(out["ProfileCreatedAt"]))
    assert got == want, f"GetProjectProfile reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
