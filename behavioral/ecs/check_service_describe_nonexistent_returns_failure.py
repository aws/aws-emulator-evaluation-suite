"""service-describe-nonexistent-returns-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-describe-nonexistent-returns-failure"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeServices reports a missing service via a single failures[] entry
    with reason MISSING and an arn naming the requested service, rather than
    silently succeeding (overly-permissive check)."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    bogus_service = ctx.unique_name("sim2real-behav-ecs-svc-missing-")

    resp = ecs.describe_services(
        cluster=cluster["clusterName"], services=[bogus_service]
    )
    assert not resp.get("services"), f"nonexistent service should not be returned, got {resp.get('services')}"
    failures = resp.get("failures", [])
    assert len(failures) == 1, f"expected exactly one failures[] entry, got {failures}"
    assert failures[0].get("reason") == "MISSING", f"expected reason MISSING, got {failures[0]}"
    assert failures[0].get("arn", "").endswith(bogus_service), (
        f"expected failure arn to name {bogus_service!r}, got {failures[0].get('arn')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
