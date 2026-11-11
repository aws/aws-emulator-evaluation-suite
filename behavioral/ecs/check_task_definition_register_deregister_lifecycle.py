"""task-definition-register-deregister-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-definition-register-deregister-lifecycle"
GROUP = "state"
SERVICES = ["ecs"]
#: Bounded convergence for a deleted revision or cluster to reach its terminal answer.
POLL_BUDGET_S = 180.0
#: The container-image prerequisite (a public image name; no container is ever started).
CONTAINER_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A task definition goes ACTIVE -> INACTIVE (still describable) -> deleted (unlisted); the
    cluster goes ACTIVE -> INACTIVE and then refuses a new service. Every service is EC2 with
    desiredCount 0, so no container ever starts."""
    ecs = ctx.client("ecs")

    # --- Cluster: created and read back ACTIVE ---
    cluster = ctx.unique_name("sim2real-behav-td-cl-")
    created = ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])["cluster"]
    cluster_arn = created["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    assert created["clusterName"] == cluster, f"expected clusterName {cluster!r}, got {created['clusterName']!r}"
    assert _cluster_status(ecs, cluster) == "ACTIVE", "a just-created cluster should describe ACTIVE"

    # --- Task definition: an EC2/bridge revision ---
    family = ctx.unique_name("sim2real-behav-td-")
    reg = _register(ecs, family)
    arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_task_def(ecs, arn))

    assert reg["status"] == "ACTIVE", f"expected ACTIVE on register, got {reg['status']}"
    assert reg["revision"] == 1, f"expected revision 1 on a fresh family, got {reg['revision']}"

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["status"] == "ACTIVE", f"expected ACTIVE on independent read, got {described['status']}"
    assert described["family"] == family, f"expected family {family!r}, got {described['family']!r}"
    assert described.get("networkMode") == "bridge", (
        f"expected networkMode 'bridge' on independent read, got {described.get('networkMode')!r}"
    )

    dereg = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]
    assert dereg["status"] == "INACTIVE", f"expected INACTIVE after deregister, got {dereg['status']}"

    described2 = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described2["status"] == "INACTIVE", "deregistered task definition should still be describable as INACTIVE"

    # Not graded: AWS documents that an INACTIVE revision may still back new services for up to
    # 10 minutes after deregistration, so that refusal has no deterministic point to assert at.

    ecs.delete_task_definitions(taskDefinitions=[arn])
    # Gone beat 1: the deleted revision reads DELETE_IN_PROGRESS or is refused.
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            got = _refusal(exc)
            expected = ("ClientException", "Unable to describe task definition.")
            assert got == expected, f"DescribeTaskDefinition on the deleted revision: expected {expected}, got {got!r}"
            break
        if status == "DELETE_IN_PROGRESS":
            break
        assert status == "INACTIVE", f"expected a deleted task definition to leave INACTIVE, got {status!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"task definition {arn} still INACTIVE after DeleteTaskDefinitions")
        time.sleep(2.0)

    # Gone beat 2: the family's ACTIVE listing does not contain it.
    active = [a for page in ecs.get_paginator("list_task_definitions").paginate(familyPrefix=family, status="ACTIVE")
              for a in page.get("taskDefinitionArns", [])]
    assert arn not in active, f"deleted task definition {arn} still listed ACTIVE: {active!r}"

    # --- Cluster: deleted, read back INACTIVE, refusing a new service ---
    # A live revision, so only the deleted cluster can be refused.
    live = _register(ecs, family)["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_task_def(ecs, live))

    deleted = ecs.delete_cluster(cluster=cluster)["cluster"]
    assert deleted["clusterArn"] == cluster_arn, f"DeleteCluster answered {deleted['clusterArn']!r}, expected {cluster_arn!r}"
    deadline = time.monotonic() + POLL_BUDGET_S
    # AWS documents that an INACTIVE cluster MAY stay discoverable for a while, so a deleted cluster
    # reads back INACTIVE or as a MISSING failure; ACTIVE/DEPROVISIONING only while it converges.
    while (status := _cluster_status(ecs, cluster)) not in ("INACTIVE", "MISSING"):
        assert status in ("ACTIVE", "DEPROVISIONING"), f"a deleted cluster should go INACTIVE, got {status!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"cluster {cluster} still {status} {POLL_BUDGET_S:.0f}s after DeleteCluster")
        time.sleep(2.0)
    got = _refused(lambda: ecs.create_service(**_service_args(ctx, cluster, live)))
    # The message tells a still-visible INACTIVE cluster ("inactive") from a gone one ("not found").
    expected_message = "The referenced cluster was inactive." if status == "INACTIVE" else "Cluster not found."
    assert got == ("ClusterNotFoundException", expected_message), (
        f"CreateService on the {status} cluster: got {got!r}"
    )


def _register(ecs, family: str) -> dict:
    """An EC2-compatible bridge-mode revision; the image is only named, never pulled."""
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {
                "name": "main",
                "image": CONTAINER_IMAGE,
                "memory": 128,
                "command": ["sleep", "60"],
                "essential": True,
            }
        ],
    )["taskDefinition"]


def _service_args(ctx, cluster: str, task_definition: str) -> dict:
    return {
        "cluster": cluster,
        "serviceName": ctx.unique_name("sim2real-behav-td-svc-"),
        "taskDefinition": task_definition,
        "desiredCount": 0,
        "launchType": "EC2",
    }


def _cluster_status(ecs, cluster: str) -> str:
    """The status DescribeClusters reports for the check's own cluster."""
    resp = ecs.describe_clusters(clusters=[cluster])
    found = [c for c in resp.get("clusters", []) if c.get("clusterName") == cluster]
    missing = [f for f in resp.get("failures", []) if f.get("reason") == "MISSING"
               and f.get("arn", "").rsplit("/", 1)[-1] == cluster]
    assert len(found) + len(missing) == 1, f"DescribeClusters({cluster}) expected one cluster or one MISSING failure, got {resp.get('clusters')!r} failures={resp.get('failures')!r}"
    return found[0].get("status") if found else "MISSING"


def _active_services(ecs, cluster: str) -> list:
    return [s for page in ecs.get_paginator("list_services").paginate(cluster=cluster)
            for s in page.get("serviceArns", [])]


def _refusal(exc, *, status=400):
    """(code, message) of a ClientError, after grading its HTTP status class."""
    err = exc.response.get('Error', {})
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {err.get('Code')}, got {got_status!r}"
    )
    return err.get('Code'), err.get('Message')


def _refused(fn, *, status=400):
    """(code, message) of the ClientError fn() raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return _refusal(exc, status=status)
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _delete_cluster(ecs, cluster: str) -> None:
    """Delete any service a target wrongly created, then the cluster; an already-deleted cluster
    (ClusterNotFoundException, or an INACTIVE one) is not a failure."""
    try:
        for arn in _active_services(ecs, cluster):
            ecs.delete_service(cluster=cluster, service=arn, force=True)
        ecs.delete_cluster(cluster=cluster)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClusterNotFoundException":
            raise


def _cleanup_task_def(ecs, arn: str) -> None:
    """Deregister and delete the revision; ECS's ClientException (already inactive/deleted) is the
    only tolerated refusal. DeleteTaskDefinitions reports a per-ARN failure instead of raising."""
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise
    try:
        ecs.delete_task_definitions(taskDefinitions=[arn])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
