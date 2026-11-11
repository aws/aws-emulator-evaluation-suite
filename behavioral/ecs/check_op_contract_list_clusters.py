"""op-contract-listClusters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listClusters"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusters paginates real clusters and rejects a garbage nextToken."""
    ecs = ctx.client("ecs")

    name_a = ctx.unique_name("sim2real-behav-cluster-a-")
    name_b = ctx.unique_name("sim2real-behav-cluster-b-")
    arn_a = ecs.create_cluster(
        clusterName=name_a, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    arn_b = ecs.create_cluster(
        clusterName=name_b, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name_a))
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name_b))

    all_arns: set[str] = set()
    token = None
    for _ in range(50):
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_clusters(**kwargs)
        all_arns.update(page["clusterArns"])
        token = page.get("nextToken")
        if not token:
            break

    assert arn_a in all_arns, "cluster A missing from paginated ListClusters"
    assert arn_b in all_arns, "cluster B missing from paginated ListClusters"

    err, message = _error(lambda: ecs.list_clusters(nextToken="sim2real-totally-bogus-token"))
    assert err == "InvalidParameterException", f"expected InvalidParameterException, got {err}"
    expected_message = 'Invalid token sim2real-totally-bogus-token'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
