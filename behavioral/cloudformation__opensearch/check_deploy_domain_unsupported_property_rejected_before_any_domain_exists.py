"""deploy-domain-unsupported-property-rejected-before-any-domain-exists."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-unsupported-property-rejected-before-any-domain-exists"
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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


def _template(domain_name: str, deployment_strategy: str) -> str:
    return json.dumps({"Resources": {"Domain": {
        "Type": "AWS::OpenSearchService::Domain",
        "Properties": {
            "DomainName": domain_name,
            "EngineVersion": _ENGINE_VERSION,
            "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 1},
            "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
            "DeploymentStrategyOptions": {"DeploymentStrategy": deployment_strategy},
            "Tags": [{"Key": "sim2real-osd", "Value": domain_name}],
        },
    }}})


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


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Domain whose DeploymentStrategyOptions.DeploymentStrategy is outside the type's enum fails
    early validation on that property before any domain exists, while the same template with
    DeploymentStrategy Default deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")
    bad_name = _compliant_domain_name(ctx, "cfnosb")
    good_name = _compliant_domain_name(ctx, "cfnosg")

    ctx.on_cleanup(lambda: _delete_domain_if_present(osc, bad_name))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-osb-stack-"),
                          _template(bad_name, "Rolling"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want = [("Domain", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "Rolling is not a valid enum value. Supported values: [Default, CapacityOptimized]",
             "/Resources/Domain/Properties/DeploymentStrategyOptions/DeploymentStrategy")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through OpenSearch, by the declared name, before any delete.
    names = [d["DomainName"] for d in osc.list_domain_names()["DomainNames"]]
    assert bad_name not in names, f"the rejected domain {bad_name!r} is listed"
    expect_error(lambda: osc.describe_domain(DomainName=bad_name),
                 *("ResourceNotFoundException", f"Domain not found: {bad_name}"))

    # Positive control: the same template, DeploymentStrategy given a valid value.
    ctx.on_cleanup(lambda: _delete_domain_if_present(osc, good_name))
    good_stack = ctx.unique_name("sim2real-osg-stack-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_name, "Default"))
    ctx.on_cleanup(lambda: _delete_slow(cfn, good_id))
    status = wait_stack(cfn, good_id, timeout_s=2100.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    domain = osc.describe_domain(DomainName=good_name)["DomainStatus"]
    cluster, ebs = domain["ClusterConfig"], domain["EBSOptions"]
    got = (domain["Created"], domain["Processing"], domain["EngineVersion"],
           cluster["InstanceType"], cluster["InstanceCount"],
           (ebs["EBSEnabled"], ebs["VolumeType"], ebs["VolumeSize"]),
           domain["DeploymentStrategyOptions"])
    want = (True, False, _ENGINE_VERSION, "t3.small.search", 1, (True, "gp3", 10),
            {"DeploymentStrategy": "Default"})
    assert got == want, f"control domain reads {got!r}, expected {want!r}"
    domain_tags = {t["Key"]: t["Value"] for t in osc.list_tags(ARN=domain["ARN"])["TagList"]
                   if not t["Key"].startswith("aws:")}
    assert domain_tags == {"sim2real": good_stack, "sim2real-osd": good_name}, (
        f"control domain tags {domain_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
