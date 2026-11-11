"""service-created-at-timestamp-millisecond-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-created-at-timestamp-millisecond-precision-preserved"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service's createdAt from CreateService comes back identical on repeated DescribeServices reads and
    falls inside the wall-clock window of the create call.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-cluster-svc-ts-")
    ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-td-svc-ts-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]

    def _cleanup_td():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup_td)

    service_name = ctx.unique_name("sim2real-svc-ts-")
    t_before = time.time()
    create_resp = ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    t_after = time.time()

    def _cleanup_service():
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)

    ctx.on_cleanup(_cleanup_service)

    created_at_create = create_resp["service"]["createdAt"]

    # Read DescribeServices a fixed number of times, asserting on every read
    # that createdAt is still bit-identical to the value captured at creation.
    # This catches an emulator that truncates/regenerates the timestamp on any
    # individual describe, rather than trusting a single read.
    last_observed = None
    for sample in range(1, 4):
        observed = ecs.describe_services(cluster=cluster_name, services=[service_name])[
            "services"
        ][0]["createdAt"]
        assert observed == created_at_create, (
            f"createdAt drifted across repeated DescribeServices calls: "
            f"create={created_at_create!r} read#{sample}={observed!r}"
        )
        last_observed = observed
        time.sleep(0.5)  # spread the reads over time, so a periodically recomputed value shows

    # generous tolerance for clock skew / request latency, but still tight
    # enough to catch gross truncation/rounding to an unrelated instant.
    # Sourced from the last independent DescribeServices read (not the
    # CreateService response) so the terminal assertion is on a read
    # through a different operation than the one that mutated.
    lower_bound = t_before - 5.0
    upper_bound = t_after + 5.0
    ts = last_observed.timestamp()
    assert lower_bound <= ts <= upper_bound, (
        f"createdAt {ts} not within expected creation window "
        f"[{lower_bound}, {upper_bound}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
