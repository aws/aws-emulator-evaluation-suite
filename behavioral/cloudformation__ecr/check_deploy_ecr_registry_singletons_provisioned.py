"""deploy-ecr-registry-singletons-provisioned."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-registry-singletons-provisioned"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_POLICY_NOT_FOUND = (
    "RegistryPolicyNotFoundException",
    "Registry policy does not exist in the registry with id '<account>'",
)


def _refusal(fn, account):
    """(Error.Code, Error.Message with the account masked) of the ClientError fn() raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(read, want, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Re-read until ``read()`` equals ``want`` (singleton resets are eventually consistent);
    return the last value read."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = read()
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


def _deploy(ctx, cfn, stack_name, template, what):
    """create_stack + wait; the stack must reach CREATE_COMPLETE."""
    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"{what} stack: expected CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    return stack_id


def _run_scanning_configuration(ctx, cfn, ecr, registry_id: str) -> None:
    """Deploy, verify and tear down AWS::ECR::RegistryScanningConfiguration."""
    before = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert before == {"scanType": "BASIC", "rules": []}, (
        f"registry scanning configuration is not at its default state before this check "
        f"ran, found {before!r}; a sibling run is using this account's registry singleton"
    )

    stack_name = ctx.unique_name("sim2real-behav-ecr-scan-stack-")
    template = json.dumps({
        "Resources": {
            "Cfg": {
                "Type": "AWS::ECR::RegistryScanningConfiguration",
                "Properties": {
                    "ScanType": "BASIC",
                    "Rules": [{
                        "RepositoryFilters": [{"Filter": "sim2real-ecr-scan-*", "FilterType": "WILDCARD"}],
                        "ScanFrequency": "SCAN_ON_PUSH",
                    }],
                },
            }
        },
        "Outputs": {"RegId": {"Value": {"Ref": "Cfg"}}},
    })
    stack_id = _deploy(ctx, cfn, stack_name, template, "scanning config")

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["RegId"] == registry_id, (
        f"Ref of RegistryScanningConfiguration must be the registry id {registry_id!r}, got {outputs['RegId']!r}"
    )
    scanning = ecr.get_registry_scanning_configuration()
    assert scanning["registryId"] == outputs["RegId"], (
        f"get_registry_scanning_configuration registryId {scanning['registryId']!r} != Ref {outputs['RegId']!r}"
    )
    described = scanning["scanningConfiguration"]
    want = {
        "scanType": "BASIC",
        "rules": [{
            "scanFrequency": "SCAN_ON_PUSH",
            "repositoryFilters": [{"filter": "sim2real-ecr-scan-*", "filterType": "WILDCARD"}],
        }],
    }
    assert described == want, f"get_registry_scanning_configuration: expected {want!r}, got {described!r}"

    delete_stack(cfn, stack_id)
    after = _poll_until(
        lambda: ecr.get_registry_scanning_configuration()["scanningConfiguration"],
        {"scanType": "BASIC", "rules": []},
    )
    assert after == {"scanType": "BASIC", "rules": []}, (
        f"deleting the stack must reset scanning configuration to its BASIC default, got {after!r}"
    )


def _run_registry_policy(ctx, cfn, ecr, registry_id: str) -> None:
    """Deploy, verify and tear down AWS::ECR::RegistryPolicy."""
    absent = _POLICY_NOT_FOUND
    before = _refusal(ecr.get_registry_policy, ctx.account)
    assert before == absent, (
        f"a registry policy already exists before this check ran: expected {absent!r}, got {before!r}"
    )

    def policy_doc(principal):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowOwnAccountDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": "ecr:DescribeRepositories",
                "Resource": "*",
            }],
        }

    stack_name = ctx.unique_name("sim2real-behav-ecr-policy-stack-")
    template = json.dumps({
        "Resources": {
            "Policy": {
                "Type": "AWS::ECR::RegistryPolicy",
                "Properties": {"PolicyText": policy_doc(
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"})},
            }
        },
        "Outputs": {"RegId": {"Value": {"Ref": "Policy"}}},
    })
    stack_id = _deploy(ctx, cfn, stack_name, template, "registry policy")

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["RegId"] == registry_id, (
        f"Ref of RegistryPolicy must be the registry id {registry_id!r}, got {outputs['RegId']!r}"
    )
    described = ecr.get_registry_policy()
    assert described["registryId"] == outputs["RegId"], (
        f"get_registry_policy registryId: expected {outputs['RegId']!r}, got {described['registryId']!r}"
    )
    want = policy_doc(f"arn:{stack_id.split(':')[1]}:iam::{ctx.account}:root")
    assert json.loads(described["policyText"]) == want, (
        f"get_registry_policy policyText: expected {want!r}, got {json.loads(described['policyText'])!r}"
    )

    delete_stack(cfn, stack_id)
    after = _poll_until(lambda: _refusal(ecr.get_registry_policy, ctx.account), absent)
    assert after == absent, (
        f"deleting the stack must remove the registry policy: expected {absent!r}, got {after!r}"
    )


def _run_replication_configuration(ctx, cfn, ecr, registry_id: str) -> None:
    """Deploy, verify and tear down AWS::ECR::ReplicationConfiguration."""
    before = ecr.describe_registry()["replicationConfiguration"]
    assert before == {"rules": []}, (
        f"replication configuration is not empty before this check ran, found {before!r}; "
        f"a sibling run is using this account's registry singleton"
    )

    # A destination other than the source region; ECR refuses replication to itself.
    dest_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-2"
    stack_name = ctx.unique_name("sim2real-behav-ecr-repl-stack-")
    template = json.dumps({
        "Resources": {
            "Repl": {
                "Type": "AWS::ECR::ReplicationConfiguration",
                "Properties": {
                    "ReplicationConfiguration": {
                        "Rules": [{"Destinations": [{"Region": dest_region, "RegistryId": registry_id}]}]
                    }
                },
            }
        },
        "Outputs": {"RegId": {"Value": {"Ref": "Repl"}}},
    })
    stack_id = _deploy(ctx, cfn, stack_name, template, "replication")

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["RegId"] == registry_id, (
        f"Ref of ReplicationConfiguration must be the registry id {registry_id!r}, got {outputs['RegId']!r}"
    )
    described = ecr.describe_registry()
    assert described["registryId"] == outputs["RegId"], (
        f"describe_registry registryId: expected {outputs['RegId']!r}, got {described['registryId']!r}"
    )
    want_rules = [{"destinations": [{"region": dest_region, "registryId": registry_id}]}]
    assert described["replicationConfiguration"]["rules"] == want_rules, (
        f"describe_registry rules: expected {want_rules!r}, "
        f"got {described['replicationConfiguration']['rules']!r}"
    )

    delete_stack(cfn, stack_id)
    after = _poll_until(lambda: ecr.describe_registry()["replicationConfiguration"], {"rules": []})
    assert after == {"rules": []}, (
        f"deleting the stack must clear the replication configuration, got {after!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:ecr-registry-scanning",
      "resource:account-singleton:ecr-registry-policy",
      "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::RegistryScanningConfiguration, RegistryPolicy and
    ReplicationConfiguration are each readable through ECR's own API with the stack's Ref and
    properties, and deleting each stack restores the registry to its prior default state.
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")

    # All three are account-wide registry singletons; run them one at a time so each
    # precondition read and its own teardown never race a sibling stage.
    registry_id = ecr.describe_registry()["registryId"]
    assert registry_id == ctx.account, (
        f"describe_registry registryId: expected the caller's account, got {registry_id!r}"
    )
    _run_scanning_configuration(ctx, cfn, ecr, registry_id)
    _run_registry_policy(ctx, cfn, ecr, registry_id)
    _run_replication_configuration(ctx, cfn, ecr, registry_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
