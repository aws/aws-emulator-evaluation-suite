"""cfn-ecs-fargate-service-in-place-update-retained-replacement-then-inactive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-fargate-service-in-place-update-retained-replacement-then-inactive"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 900.0
_GONE_CAP_S = 300.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
#: A deployment reaches its steady state, and an old one drains, within minutes.
_CONVERGE_CAP_S = 300.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: CloudFormation's reason on the event that starts a replacement.
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)

#: ECS's refusal to update a service that is no longer ACTIVE.
_NOT_ACTIVE = ("ServiceNotActiveException", "Service was not ACTIVE.")

#: ECS's refusal of a task definition revision it cannot describe.
_NO_REVISION = ("ClientException", "Unable to describe task definition.")

#: ECS's refusal to delete a service, or a cluster, in a cluster that does not exist.
_NO_CLUSTER = ("ClusterNotFoundException", "Cluster not found.")

#: ECS's refusal to delete a service that does not exist; the message is empty.
_NO_SERVICE = ("ServiceNotFoundException", "")

#: Never pulled: every revision of the service runs zero tasks.
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

#: The deployment configurations: max percent, min healthy percent, circuit breaker enabled.
_V1 = (100, 0, False)

#: The circuit breaker members ECS reports beside the two the template sets.
_BREAKER_DEFAULTS = {
    "resetOnHealthyTask": True,
    "thresholdConfiguration": {"type": "BOUNDED_PERCENT", "value": 50},
}
_V2 = (150, 50, True)


def _template(name: str, cluster: str, task_definition: str, net, deployment: tuple) -> str:
    maximum, minimum, breaker = deployment
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Service": {
                    "Type": "AWS::ECS::Service",
                    # ServiceName is create-only, so changing it replaces the service.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ServiceName": name,
                        "Cluster": cluster,
                        "TaskDefinition": task_definition,
                        "LaunchType": "FARGATE",
                        "DesiredCount": 0,
                        "NetworkConfiguration": {
                            "AwsvpcConfiguration": {
                                "Subnets": list(net.subnet_ids[:2]),
                                "SecurityGroups": [net.security_group_id],
                                "AssignPublicIp": "DISABLED",
                            }
                        },
                        "DeploymentConfiguration": {
                            "MaximumPercent": maximum,
                            "MinimumHealthyPercent": minimum,
                            "DeploymentCircuitBreaker": {"Enable": breaker, "Rollback": breaker},
                        },
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "Name": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
                "ServiceArn": {"Value": {"Fn::GetAtt": ["Service", "ServiceArn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation Fargate service at zero tasks reads back as templated and deploys.

    A task definition and deployment change keeps the service and rolls one new deployment; a
    ServiceName change under Retain keeps the old service ACTIVE; deleted: ServiceNotActive.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-service.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    network = ctx.network()
    cluster = ctx.unique_name("sim2real-cfnsvc-cl-")
    family = ctx.unique_name("sim2real-cfnsvc-td-")
    first = ctx.unique_name("sim2real-cfnsvc-a-")
    second = ctx.unique_name("sim2real-cfnsvc-b-")
    stack_name = ctx.unique_name("sim2real-cfnsvc-stack-")
    ref = {"stack": stack_name}
    revisions: list[str] = []

    # LIFO: the stack goes first, then the retained service, then the revisions and the cluster.
    # Teardown waits share one deadline of their own: the body's deadline does not bound cleanup.
    limit: dict = {}
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    ctx.on_cleanup(lambda: _retire_task_definitions(ecs, revisions))
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, first, limit))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))

    cluster_arn = ecs.create_cluster(
        clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]["clusterArn"]
    for revision in ("one", "two"):
        revisions.append(_register(ecs, family, revision))
    rev1, rev2 = revisions

    # ---- 1. create: CloudFormation's view, ECS's view, the deployment reaches steady state
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, cluster_arn, rev1, network, _V1),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_arn = _physical_ids(cfn, ref["stack"])["Service"]
    assert _outputs(stack) == {"Name": first, "ServiceArn": first_arn}, (
        f"GetAtt outputs {_outputs(stack)!r}"
    )
    _assert_service(ctx, ecs, cluster_arn, first_arn, first, rev1, network, _V1)
    _assert_steady(ctx, ecs, cluster_arn, first_arn, rev1)

    # ---- 2. in-place: a new revision and deployment configuration, the same service
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, cluster_arn, rev2, network, _V2),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Service"] == first_arn, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Service"), first_arn, "Service")
    _assert_service(ctx, ecs, cluster_arn, first_arn, first, rev2, network, _V2)
    _assert_steady(ctx, ecs, cluster_arn, first_arn, rev2)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new service, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, cluster_arn, rev2, network, _V2),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = _physical_ids(cfn, ref["stack"])["Service"]
    assert second_arn != first_arn, f"the replacement must be a new service, still {first_arn!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Service"), first_arn, second_arn, "Service"
    )
    assert _outputs(stack) == {"Name": second, "ServiceArn": second_arn}, (
        f"GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_service(ctx, ecs, cluster_arn, second_arn, second, rev2, network, _V2)
    _assert_steady(ctx, ecs, cluster_arn, second_arn, rev2)
    _assert_service(ctx, ecs, cluster_arn, first_arn, first, rev2, network, _V2)

    # ---- 4. delete: the stack's service is INACTIVE and refuses updates; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    gone = _poll(
        ctx,
        lambda: _describe(ecs, cluster_arn, second_arn),
        lambda d: d["status"] == "INACTIVE",
        f"service {second} INACTIVE",
        _GONE_CAP_S,
    )
    assert (gone["desiredCount"], gone["runningCount"]) == (0, 0), (
        f"the deleted service must run nothing, got {gone!r}"
    )
    got = _error(
        lambda: ecs.update_service(cluster=cluster_arn, service=second_arn, desiredCount=0)
    )
    assert got == _NOT_ACTIVE, f"UpdateService on the deleted service: {got!r}"
    _assert_service(ctx, ecs, cluster_arn, first_arn, first, rev2, network, _V2)


def _register(ecs, family: str, revision: str) -> str:
    """Register one Fargate revision of *family*; return its ARN."""
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": _IMAGE,
                "essential": True,
                "environment": [{"name": "REVISION", "value": revision}],
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]


def _describe(ecs, cluster_arn: str, arn: str) -> dict:
    """DescribeServices with tags, reduced to the template's view and the deployments."""
    resp = ecs.describe_services(cluster=cluster_arn, services=[arn], include=["TAGS"])
    assert resp.get("failures", []) == [], f"DescribeServices {arn}: {resp['failures']!r}"
    (svc,) = resp["services"]
    vpc = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
    config = svc.get("deploymentConfiguration", {})
    return {
        "serviceArn": svc.get("serviceArn"),
        "serviceName": svc.get("serviceName"),
        "clusterArn": svc.get("clusterArn"),
        "status": svc.get("status"),
        "taskDefinition": svc.get("taskDefinition"),
        "launchType": svc.get("launchType"),
        "platformVersion": svc.get("platformVersion"),
        "schedulingStrategy": svc.get("schedulingStrategy"),
        "desiredCount": svc.get("desiredCount"),
        "runningCount": svc.get("runningCount"),
        "pendingCount": svc.get("pendingCount"),
        "network": (
            sorted(vpc.get("subnets", [])),
            vpc.get("securityGroups"),
            vpc.get("assignPublicIp"),
        ),
        "deployment": (
            config.get("maximumPercent"),
            config.get("minimumHealthyPercent"),
            config.get("deploymentCircuitBreaker"),
        ),
        "tags": {
            t["key"]: t["value"] for t in svc.get("tags", []) if not t["key"].startswith("aws:")
        },
        "deployments": [
            (
                d.get("status"),
                d.get("taskDefinition"),
                d.get("desiredCount"),
                d.get("runningCount"),
                d.get("rolloutState"),
            )
            for d in svc.get("deployments", [])
        ],
    }


def _assert_service(ctx, ecs, cluster_arn, arn, name, task_definition, net, deployment) -> None:
    """DescribeServices reports the template's ACTIVE service exactly."""
    maximum, minimum, breaker = deployment
    want = {
        "serviceArn": arn,
        "serviceName": name,
        "clusterArn": cluster_arn,
        "status": "ACTIVE",
        "taskDefinition": task_definition,
        "launchType": "FARGATE",
        "platformVersion": "LATEST",
        "schedulingStrategy": "REPLICA",
        "desiredCount": 0,
        "runningCount": 0,
        "pendingCount": 0,
        "network": (sorted(net.subnet_ids[:2]), [net.security_group_id], "DISABLED"),
        "deployment": (
            maximum,
            minimum,
            {**_BREAKER_DEFAULTS, "enable": breaker, "rollback": breaker},
        ),
        "tags": {"sim2real": CHECK},
    }

    def view():
        d = _describe(ecs, cluster_arn, arn)
        return {k: d[k] for k in want}

    got = _poll(ctx, view, lambda d: d == want, f"service {name} as templated")
    assert got == want, f"service {name}: {got!r}, expected {want!r}"


def _assert_steady(ctx, ecs, cluster_arn: str, arn: str, task_definition: str) -> None:
    """One PRIMARY deployment of *task_definition* completes at zero tasks; no task runs."""
    want = [("PRIMARY", task_definition, 0, 0, "COMPLETED")]
    got = _poll(
        ctx,
        lambda: _describe(ecs, cluster_arn, arn)["deployments"],
        lambda d: d == want,
        f"steady deployment of {arn}",
    )
    assert got == want, f"deployments of {arn}: {got!r}, expected {want!r}"
    tasks = ecs.list_tasks(cluster=cluster_arn, serviceName=arn.rsplit("/", 1)[-1])["taskArns"]
    assert tasks == [], f"a service at desired count 0 runs no task, got {tasks!r}"


def _delete_service(ecs, cluster: str, name: str, limit: dict) -> None:
    """Delete the retained service and wait until it is INACTIVE, so the cluster can go."""
    try:
        ecs.delete_service(cluster=cluster, service=name, force=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if (err["Code"], err.get("Message")) in (_NO_CLUSTER, _NO_SERVICE):
            return
        if err["Code"] != "ServiceNotActiveException":
            raise
    _poll(
        None,
        lambda: ecs.describe_services(cluster=cluster, services=[name])["services"],
        lambda s: all(x["status"] == "INACTIVE" for x in s),
        f"service {name} INACTIVE",
        _remaining(limit),
    )


def _retire_task_definitions(ecs, arns: list[str]) -> None:
    """Deregister then delete each revision; a missing one is done."""
    for arn in arns:
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err.get("Message")) != _NO_REVISION:
                raise
    if arns:
        failures = ecs.delete_task_definitions(taskDefinitions=arns).get("failures", [])
        if failures:
            raise AssertionError(f"task definition teardown failed: {failures!r}")


def _delete_cluster(ecs, name: str) -> None:
    try:
        ecs.delete_cluster(cluster=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if (err["Code"], err.get("Message")) != _NO_CLUSTER:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes no ctx: it waits the full cap.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are an in-place update ending on *physical_id*.

    Repeated statuses collapse: a type may add an UPDATE_IN_PROGRESS row while it stabilizes.
    """
    statuses = [s for i, (s, _, _) in enumerate(rows) if i == 0 or rows[i - 1][0] != s]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert not [r for r in rows if r[1] == _REPLACING or r[0].startswith(("CREATE_", "DELETE_"))], (
        f"{logical_id} must not be created, deleted or replaced, its events were {rows!r}"
    )
    assert rows[-1][0] == "UPDATE_COMPLETE" and rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        _REPLACING,
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


def _poll(ctx, read, done, what: str, cap_s: float = _CONVERGE_CAP_S):
    """Poll ``read()`` until ``done(value)``; return that value (an eventually consistent read)."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}; last {value!r}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
