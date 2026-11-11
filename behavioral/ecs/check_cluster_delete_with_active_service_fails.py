"""cluster-delete-with-active-service-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-delete-with-active-service-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cluster that still has an ACTIVE service registered on it must refuse deletion
    (overly-permissive check): the rejected delete leaves the cluster untouched, and once
    the blocking service is gone the identical DeleteCluster call succeeds."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=cluster_name)["cluster"]
    ctx.on_cleanup(lambda c=cluster: _delete_cluster_if_present(ecs, c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster["clusterName"],
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=0,
    )
    ctx.on_cleanup(lambda: _delete_service_if_present(ecs, cluster["clusterName"], svc_name))

    refused = _expect_error(lambda: ecs.delete_cluster(cluster=cluster["clusterName"]),
                            ("ClusterContainsServicesException",))
    expected_message = "The Cluster cannot be deleted while Services are active."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # effect absent: the rejected delete must not have touched the cluster
    desc = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert desc and desc[0]["status"] == "ACTIVE", (
        f"cluster should be untouched by the rejected DeleteCluster call, got {desc}"
    )

    # restore: remove the one blocking condition, then the identical call must succeed
    ecs.delete_service(cluster=cluster_name, service=svc_name, force=True)
    _poll_service_gone(ecs, cluster_name, svc_name)
    ecs.delete_cluster(cluster=cluster_name)
    # Gone beat 1: the cluster reads INACTIVE or is reported MISSING (ECS keeps a tombstone).
    remaining = ecs.describe_clusters(clusters=[cluster_name])
    statuses = [c["status"] for c in remaining.get("clusters", [])]
    missing = [f.get("reason") for f in remaining.get("failures", [])]
    assert statuses == ["INACTIVE"] or (not statuses and missing == ["MISSING"]), (
        f"expected the deleted cluster INACTIVE or MISSING, got clusters {statuses!r} failures {missing!r}"
    )
    # Gone beat 2: the cluster listing no longer contains it (bounded convergence).
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        arns = [a for page in ecs.get_paginator("list_clusters").paginate() for a in page.get("clusterArns", [])]
        if cluster["clusterArn"] not in arns:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"deleted cluster {cluster_name} still listed by ListClusters")
        time.sleep(2.0)
    # Gone beat 3: creating a service on the dead cluster is refused.
    refused = _expect_error(lambda: ecs.create_service(cluster=cluster_name, serviceName=ctx.unique_name("sim2real-behav-ecs-svc-"),
                                                       taskDefinition=td["taskDefinitionArn"], desiredCount=0),
                            ("ClusterNotFoundException",))
    expected_message = "The referenced cluster was inactive."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _delete_cluster_if_present(ecs, name):
    try:
        ecs.delete_cluster(cluster=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClusterNotFoundException":
            raise


def _delete_service_if_present(ecs, cluster_name, svc_name):
    try:
        ecs.delete_service(cluster=cluster_name, service=svc_name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException"):
            raise


def _poll_service_gone(ecs, cluster_name, service_name, timeout_s=POLL_BUDGET_S, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
        if not described or described[0]["status"] == "INACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"service {service_name} did not reach INACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
