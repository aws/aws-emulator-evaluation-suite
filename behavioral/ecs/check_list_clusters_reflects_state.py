"""list-clusters-reflects-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-clusters-reflects-state"
GROUP = 'cluster-lifecycle'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusters includes a cluster right after creation and stops
    including it (or marks it non-ACTIVE) after deletion."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    name = cluster["clusterName"]
    arn = cluster["clusterArn"]

    arns = [
        a
        for page in ecs.get_paginator("list_clusters").paginate()
        for a in page.get("clusterArns", [])
    ]
    assert arn in arns, f"newly created cluster {arn} missing from ListClusters, saw {arns}"

    ecs.delete_cluster(cluster=name)
    _deadline = time.monotonic() + 30
    while True:
        arns = [
            a
            for page in ecs.get_paginator("list_clusters").paginate()
            for a in page.get("clusterArns", [])
        ]
        if arn not in arns:
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"deleted cluster {arn} still present in ListClusters after 30s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
