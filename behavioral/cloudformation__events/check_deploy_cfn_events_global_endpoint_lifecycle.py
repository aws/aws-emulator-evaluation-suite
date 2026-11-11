"""deploy-cfn-events-global-endpoint-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-events-global-endpoint-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "route53"]

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


#: A calculated health check with no children dials nothing: Route 53 probes no third party.
_HEALTH_CHECK = {"Type": "CALCULATED", "ChildHealthChecks": [], "HealthThreshold": 0}


def _endpoint_not_found(name: str, region: str) -> tuple[str, str]:
    return ("ResourceNotFoundException", f"Endpoint {name} does not exist in region {region}.")


def _health_check_not_found(hc_id: str) -> tuple[str, str]:
    return ("NoSuchHealthCheck", f"A health check with id {hc_id} does not exist.")


def _secondary_region(region: str) -> str:
    """A failover region guaranteed to differ from the check's own region."""
    return "us-west-2" if region == "us-east-1" else "us-east-1"
def _template(secondary: str, bus_name: str, endpoint_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": bus_name}},
                "HealthCheck": {
                    "Type": "AWS::Route53::HealthCheck",
                    "Properties": {
                        "HealthCheckConfig": _HEALTH_CHECK
                    },
                },
                "Endpoint": {
                    "Type": "AWS::Events::Endpoint",
                    "Properties": {
                        "Name": endpoint_name,
                        "RoutingConfig": {
                            "FailoverConfig": {
                                "Primary": {
                                    "HealthCheck": {
                                        "Fn::Sub": "arn:${AWS::Partition}:route53:::healthcheck/${HealthCheck}"
                                    }
                                },
                                "Secondary": {"Route": secondary},
                            }
                        },
                        "ReplicationConfig": {"State": "DISABLED"},
                        "EventBuses": [
                            {"EventBusArn": {"Fn::GetAtt": ["Bus", "Arn"]}},
                            {
                                "EventBusArn": {
                                    "Fn::Sub": (
                                        f"arn:${{AWS::Partition}}:events:{secondary}:"
                                        "${AWS::AccountId}:event-bus/${Bus}"
                                    )
                                }
                            },
                        ],
                    },
                },
            },
            "Outputs": {
                "EndpointRef": {"Value": {"Ref": "Endpoint"}},
                "EndpointArn": {"Value": {"Fn::GetAtt": ["Endpoint", "Arn"]}},
                "EndpointId": {"Value": {"Fn::GetAtt": ["Endpoint", "EndpointId"]}},
                "EndpointUrl": {"Value": {"Fn::GetAtt": ["Endpoint", "EndpointUrl"]}},
                "HealthCheckId": {"Value": {"Ref": "HealthCheck"}},
                "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation global Events Endpoint, its EventBus and Route 53 health check read back.

    DescribeEndpoint matches the Ref, routing (health check, a secondary region distinct from the
    stack's), event buses and GetAtts; deleting the stack removes the endpoint and health check.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    route53 = ctx.client("route53")
    secondary = _secondary_region(ctx.region)
    bus_name = ctx.unique_name("sim2real-behav-evepbus-")
    endpoint_name = ctx.unique_name("sim2real-behav-evep-")
    stack_name = ctx.unique_name("sim2real-behav-evep-stack-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(secondary, bus_name, endpoint_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    bus_arn_primary = f"arn:{partition}:events:{ctx.region}:{ctx.account}:event-bus/{bus_name}"
    bus_arn_secondary = f"arn:{partition}:events:{secondary}:{ctx.account}:event-bus/{bus_name}"
    hc_id = outputs["HealthCheckId"]

    bus = events.describe_event_bus(Name=bus_name)
    assert (bus["Name"], bus["Arn"]) == (bus_name, bus_arn_primary) == (bus_name, outputs["BusArn"]), (
        f"event bus reads {(bus['Name'], bus['Arn'])!r}"
    )
    hc_config = route53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]["HealthCheckConfig"]
    # Route 53's XML drops an empty list, so an absent ChildHealthChecks reads as [].
    got = {k: hc_config.get(k, [] if k == "ChildHealthChecks" else None) for k in _HEALTH_CHECK}
    assert got == _HEALTH_CHECK, f"health check {hc_id!r} reads {got!r}, expected {_HEALTH_CHECK!r}"
    assert outputs["EndpointRef"] == endpoint_name, (
        f"Ref on the endpoint should be its name, got {outputs['EndpointRef']!r}"
    )

    state = _wait_endpoint_state(events, endpoint_name)
    assert state == "ACTIVE", f"expected the settled endpoint State ACTIVE, got {state!r}"

    endpoint = events.describe_endpoint(Name=endpoint_name)
    assert endpoint["Arn"] == outputs["EndpointArn"], (
        f"GetAtt Endpoint.Arn {outputs['EndpointArn']!r} must match DescribeEndpoint's "
        f"{endpoint['Arn']!r}"
    )
    assert endpoint["EndpointId"] == outputs["EndpointId"], (
        f"GetAtt Endpoint.EndpointId {outputs['EndpointId']!r} must match DescribeEndpoint's "
        f"{endpoint['EndpointId']!r}"
    )
    assert endpoint["EndpointUrl"] == outputs["EndpointUrl"], (
        f"GetAtt Endpoint.EndpointUrl {outputs['EndpointUrl']!r} must match DescribeEndpoint's "
        f"{endpoint['EndpointUrl']!r}"
    )
    failover = endpoint["RoutingConfig"]["FailoverConfig"]
    want = {"Primary": {"HealthCheck": f"arn:{partition}:route53:::healthcheck/{hc_id}"},
            "Secondary": {"Route": secondary}}
    assert failover == want, f"FailoverConfig {failover!r}, expected {want!r}"
    assert endpoint["ReplicationConfig"]["State"] == "DISABLED", (
        f"expected ReplicationConfig.State DISABLED, got {endpoint['ReplicationConfig']!r}"
    )
    bus_arns = {b["EventBusArn"] for b in endpoint["EventBuses"]}
    assert bus_arns == {bus_arn_primary, bus_arn_secondary}, (
        f"expected the template's two event bus Arns {sorted([bus_arn_primary, bus_arn_secondary])!r}, "
        f"got {sorted(bus_arns)!r}"
    )

    delete_stack(cfn, stack_id)
    endpoint_gone = _endpoint_not_found(endpoint_name, ctx.region)
    health_check_gone = _health_check_not_found(hc_id)
    expect_error(lambda: events.describe_endpoint(Name=endpoint_name), *endpoint_gone)
    expect_error(lambda: route53.get_health_check(HealthCheckId=hc_id), *health_check_gone)


_ENDPOINT_TERMINAL = {"ACTIVE", "CREATE_FAILED"}


def _wait_endpoint_state(events, name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    """Poll DescribeEndpoint to a terminal State (never assert a transitional CREATING)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = events.describe_endpoint(Name=name)["State"]
        if last in _ENDPOINT_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} did not settle within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
