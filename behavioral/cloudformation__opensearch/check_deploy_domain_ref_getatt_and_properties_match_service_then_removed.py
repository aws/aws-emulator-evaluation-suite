"""deploy-domain-ref-getatt-and-properties-match-service-then-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-ref-getatt-and-properties-match-service-then-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "opensearch"]

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

_ENGINE_VERSION = "OpenSearch_2.19"
_TEARDOWN_S = 1700.0  # a delete that outlasts the 600 s per-stack budget, within the suite's 1800 s


def _template(domain_name: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "Domain": {
                    "Type": "AWS::OpenSearchService::Domain",
                    "Properties": {
                        "DomainName": domain_name,
                        "EngineVersion": _ENGINE_VERSION,
                        "ClusterConfig": {
                            "InstanceType": "t3.small.search",
                            "InstanceCount": 1,
                            "DedicatedMasterEnabled": False,
                            "ZoneAwarenessEnabled": False,
                        },
                        "EBSOptions": {
                            "EBSEnabled": True,
                            "VolumeType": "gp3",
                            "VolumeSize": 10,
                        },
                        "DomainEndpointOptions": {"EnforceHTTPS": True},
                        "Tags": [{"Key": "sim2real-osd", "Value": domain_name}],
                    },
                }
            },
            "Outputs": {
                "DomainRef": {"Value": {"Ref": "Domain"}},
                "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "Id"]}},
                "DomainArn": {"Value": {"Fn::GetAtt": ["Domain", "Arn"]}},
                "DomainEndpointOut": {"Value": {"Fn::GetAtt": ["Domain", "DomainEndpoint"]}},
            },
        }
    )


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _delete_slow(cfn, stack_id: str) -> None:
    """delete_stack for a domain stack: wait out a create, delete, wait in one budget, then grade."""
    deadline = time.monotonic() + _TEARDOWN_S
    status = wait_stack(cfn, stack_id, timeout_s=_TEARDOWN_S)
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                   deadline - time.monotonic())
    delete_stack(cfn, stack_id)


def _delete_domain_if_present(osc, domain_name: str) -> None:
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-deployed Domain's Ref, every GetAtt output, every set property and the tags
    match OpenSearch's own reads; deleting the stack removes it, confirmed the same way.
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")

    domain_name = _compliant_domain_name(ctx, "cfnosd")
    stack_name = ctx.unique_name("sim2real-osd-stack-")

    ctx.on_cleanup(lambda: _delete_domain_if_present(osc, domain_name))
    stack_id = create_stack(ctx, cfn, stack_name, _template(domain_name))
    ctx.on_cleanup(lambda: _delete_slow(cfn, stack_id))
    status = wait_stack(cfn, stack_id, timeout_s=2100.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref against the (unpaged) ListDomainNames entry by name, never a read keyed by the Ref.
    listed = [d["DomainName"] for d in osc.list_domain_names()["DomainNames"]
              if d["DomainName"] == domain_name]
    assert listed == [outputs["DomainRef"]] == [domain_name], (
        f"ListDomainNames {listed!r}, Ref {outputs['DomainRef']!r}, declared {domain_name!r}"
    )

    status = osc.describe_domain(DomainName=listed[0])["DomainStatus"]
    assert (status["Created"], status["Processing"]) == (True, False), (
        f"Created/Processing {(status['Created'], status['Processing'])!r}"
    )
    got = (outputs["DomainId"], outputs["DomainArn"], outputs["DomainEndpointOut"])
    want = (status["DomainId"], status["ARN"], status["Endpoint"])
    assert got == want, f"GetAtt Id/Arn/DomainEndpoint {got!r}, DescribeDomain {want!r}"

    assert status["EngineVersion"] == _ENGINE_VERSION, f"EngineVersion {status['EngineVersion']!r}"
    cluster = status["ClusterConfig"]
    got = (cluster["InstanceType"], cluster["InstanceCount"], cluster["DedicatedMasterEnabled"],
           cluster["ZoneAwarenessEnabled"])
    assert got == ("t3.small.search", 1, False, False), f"ClusterConfig {cluster!r}"
    ebs = status["EBSOptions"]
    got = (ebs["EBSEnabled"], ebs["VolumeType"], ebs["VolumeSize"])
    assert got == (True, "gp3", 10), f"EBSOptions {ebs!r}"
    assert status["DomainEndpointOptions"]["EnforceHTTPS"] is True, (
        f"DomainEndpointOptions {status['DomainEndpointOptions']!r}"
    )
    domain_tags = {t["Key"]: t["Value"] for t in osc.list_tags(ARN=status["ARN"])["TagList"]
                   if not t["Key"].startswith("aws:")}
    assert domain_tags == {"sim2real": stack_name, "sim2real-osd": domain_name}, (
        f"domain tags {domain_tags!r}"
    )

    _delete_slow(cfn, stack_id)
    expect_error(lambda: osc.describe_domain(DomainName=domain_name),
                 *("ResourceNotFoundException", f"Domain not found: {domain_name}"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
