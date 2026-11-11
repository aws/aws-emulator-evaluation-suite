"""service-deployment-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-deployment-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """createdAt on a service and on its primary deployment is a fixed point-in-time value:
    repeated DescribeServices calls return the exact same datetime (no drift from
    recomputing "now" on each read, no truncation of sub-second precision)."""
    ecs = ctx.client("ecs")
    check_tags = [{"key": "sim2real-check", "value": CHECK}]

    cluster_name = ctx.unique_name("sim2real-ecs-tsprec-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=check_tags)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-tsprec-td-")
    # desiredCount=0 with the default (EC2) launch type needs no capacity providers, VPC or
    # actual container instances -- it only exercises the service/deployment bookkeeping, and
    # avoids depending on an ambient default VPC that a freshly provisioned account may lack.
    taskdef_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "memory": 128, "essential": True}
        ],
        tags=check_tags,
    )["taskDefinition"]["taskDefinitionArn"]

    def _cleanup_taskdef():
        ecs.deregister_task_definition(taskDefinition=taskdef_arn)
        ecs.delete_task_definitions(taskDefinitions=[taskdef_arn])

    ctx.on_cleanup(_cleanup_taskdef)

    service_name = ctx.unique_name("sim2real-ecs-tsprec-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=taskdef_arn,
        desiredCount=0,
        tags=check_tags,
    )["service"]["serviceArn"]

    def _cleanup_service():
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            desc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"]
            if not desc or desc[0]["status"] == "INACTIVE":
                return
            time.sleep(3)

    ctx.on_cleanup(_cleanup_service)

    first = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    first_dep = next(d for d in first["deployments"] if d["status"] == "PRIMARY")

    # Read DescribeServices a fixed number of times and demand the freeze hold on every
    # read, not just a before/after pair: an emulator that recomputes "now" only
    # occasionally would slip past a single gap.
    for sample in range(1, 5):
        observed = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
        observed_dep = next(d for d in observed["deployments"] if d["status"] == "PRIMARY")

        assert observed["createdAt"] == first["createdAt"], (
            f"service.createdAt drifted across DescribeServices calls: {first['createdAt']!r} "
            f"!= {observed['createdAt']!r} (read #{sample})"
        )
        assert observed_dep["createdAt"] == first_dep["createdAt"], (
            f"primary deployment createdAt drifted across DescribeServices calls: "
            f"{first_dep['createdAt']!r} != {observed_dep['createdAt']!r} (read #{sample})"
        )
        assert observed_dep["id"] == first_dep["id"], (
            f"primary deployment identity changed across reads: "
            f"{first_dep['id']!r} != {observed_dep['id']!r} (read #{sample})"
        )
        time.sleep(1.5)  # spread the reads over time, so a periodically recomputed "now" shows


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
