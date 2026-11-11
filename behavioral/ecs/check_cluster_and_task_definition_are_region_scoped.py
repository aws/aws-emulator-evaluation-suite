"""cluster-and-task-definition-are-region-scoped."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-and-task-definition-are-region-scoped"
GROUP = 'region-partitioning'
SERVICES = ['ecs']

_CONTAINERS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "memory": 64,
        "essential": True,
    }
]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) ``fn`` raises. An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_task_definition(ecs, arn: str) -> None:
    ecs.deregister_task_definition(taskDefinition=arn)
    ecs.delete_task_definitions(taskDefinitions=[arn])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster and a task definition created in one region do not exist in another: there the name
    is MISSING, the home ARN is refused as naming another region, the family is undescribable and
    unlisted, and DeleteCluster is refused, while the home region still serves both ACTIVE.
    """
    # Any commercial region other than ctx.region would do; this is not a region-pinned resource.
    other_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    home = ctx.client("ecs")
    away = ctx.client("ecs", region=other_region)
    name = ctx.unique_name("sim2real-behav-ecs-region-")

    cluster = home.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]
    ctx.on_cleanup(_teardown(lambda: home.delete_cluster(cluster=name), "ClusterNotFoundException"))
    cluster_arn = cluster["clusterArn"]
    assert cluster_arn == f"arn:aws:ecs:{ctx.region}:{ctx.account}:cluster/{name}", (
        f"cluster ARN has the wrong shape for the home region: {cluster_arn!r}"
    )

    td = home.register_task_definition(
        family=name, containerDefinitions=_CONTAINERS,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(home, td_arn))
    assert td_arn == f"arn:aws:ecs:{ctx.region}:{ctx.account}:task-definition/{name}:1", (
        f"task definition ARN has the wrong shape for the home region: {td_arn!r}"
    )

    # Positive control: the home region serves both.
    got = home.describe_clusters(clusters=[name])
    assert [c["status"] for c in got["clusters"]] == ["ACTIVE"] and not got["failures"], (
        f"home-region DescribeClusters did not return the cluster ACTIVE: {got!r}"
    )
    home_families = [
        f for page in home.get_paginator("list_task_definition_families").paginate(familyPrefix=name)
        for f in page["families"]
    ]
    assert home_families == [name], f"home-region family listing was {home_families!r}"

    # The second region resolves the bare name against itself and reports it MISSING.
    away_desc = away.describe_clusters(clusters=[name])
    assert away_desc["clusters"] == [], (
        f"a second region described the home cluster: {away_desc['clusters']!r}"
    )
    want_failure = [{
        "arn": f"arn:aws:ecs:{other_region}:{ctx.account}:cluster/{name}",
        "reason": "MISSING",
    }]
    assert away_desc["failures"] == want_failure, (
        f"second-region DescribeClusters failures were {away_desc['failures']!r}, "
        f"expected one MISSING failure naming that region's ARN"
    )

    # The home ARN is refused outright: it names a region the endpoint does not serve.
    code, msg = _error(lambda: away.describe_clusters(clusters=[cluster_arn]))
    assert (code, msg) == ("InvalidParameterException", "Invalid Region in ARN"), (
        f"second-region DescribeClusters with the home ARN gave {(code, msg)!r}"
    )

    away_clusters = [
        a for page in away.get_paginator("list_clusters").paginate() for a in page["clusterArns"]
    ]
    leaked = [a for a in away_clusters if a.endswith(f":cluster/{name}")]
    assert leaked == [], f"second-region ListClusters carries the home cluster: {leaked!r}"

    code, msg = _error(lambda: away.describe_task_definition(taskDefinition=name))
    assert (code, msg) == ("ClientException", "Unable to describe task definition."), (
        f"second-region DescribeTaskDefinition of the family gave {(code, msg)!r}"
    )
    away_families = [
        f for page in away.get_paginator("list_task_definition_families").paginate(familyPrefix=name)
        for f in page["families"]
    ]
    assert away_families == [], f"second-region family listing was {away_families!r}"

    # A mutation aimed at the second region cannot reach the home cluster.
    code, msg = _error(lambda: away.delete_cluster(cluster=name))
    assert (code, msg) == ("ClusterNotFoundException", "Cluster not found."), (
        f"second-region DeleteCluster gave {(code, msg)!r}"
    )
    after = home.describe_clusters(clusters=[name])
    assert [c["status"] for c in after["clusters"]] == ["ACTIVE"], (
        f"the home cluster changed after a second-region DeleteCluster: {after!r}"
    )
    td_after = home.describe_task_definition(taskDefinition=name)["taskDefinition"]
    assert (td_after["status"], td_after["revision"]) == ("ACTIVE", 1), (
        f"home task definition is {td_after['status']!r} revision {td_after['revision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
