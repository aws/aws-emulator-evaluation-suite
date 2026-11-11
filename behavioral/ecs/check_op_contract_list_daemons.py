"""op-contract-listDaemons."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listDaemons"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDaemons returns an empty list for a daemon-free (or nonexistent-but-valid-ARN) cluster and rejects a malformed cluster ARN."""
    ecs = ctx.client("ecs")

    if not hasattr(ecs, "list_daemons"):
        raise AssertionError("unreachable: boto3 ecs client in this environment has no list_daemons operation")

    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    from botocore.exceptions import ClientError

    try:
        resp = ecs.list_daemons(clusterArn=cluster_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "UnsupportedFeatureException":
            raise AssertionError(
                "unreachable: ECS daemon services are not enabled for this account/region"
            )
        raise

    assert resp["daemonSummariesList"] == [], (
        f"expected a fresh daemon-free cluster to report no daemons, got {resp['daemonSummariesList']!r}"
    )
    assert "nextToken" not in resp or resp["nextToken"] is None, (
        f"expected no pagination token for an empty result, got {resp.get('nextToken')!r}"
    )

    # A well-formed cluster ARN that simply doesn't exist yet (but is otherwise a
    # syntactically valid, same-account/same-region ECS cluster ARN) doesn't trip
    # ClusterNotFoundException here the way it does for many other cluster-scoped
    # List/Describe operations -- ListDaemons just finds no daemons scoped to that ARN and
    # returns an empty list. Verify that non-erroring behavior directly, and separately prove
    # rejection with a cluster identifier that's actually malformed (not a valid ARN at all),
    # which real AWS does reject.
    nonexistent_cluster_arn = cluster_arn.rsplit("/", 1)[0] + "/sim2real-nope"
    empty_resp = ecs.list_daemons(clusterArn=nonexistent_cluster_arn)
    assert empty_resp["daemonSummariesList"] == [], (
        f"expected a well-formed but nonexistent cluster ARN to report no daemons, got "
        f"{empty_resp['daemonSummariesList']!r}"
    )

    # A plain hyphenated string like "not-a-cluster-arn-at-all" is a structurally valid
    # cluster NAME (ECS cluster-scoped operations accept either a name or an ARN), so real AWS
    # doesn't reject it -- it resolves the same way `nonexistent_cluster_arn` did above (no
    # matching cluster, empty daemon list). To actually exercise rejection, use an identifier
    # that violates the cluster name/ARN syntax outright (embedded whitespace and punctuation
    # that neither a bare name nor an ARN can contain).
    code, message = _error(lambda: ecs.list_daemons(clusterArn="not a valid cluster arn??"))
    assert code == "ServerException", (
        f"expected ServerException for a structurally invalid (non-ARN, non-name) "
        f"cluster identifier, got {code!r}"
    )
    expected_message = 'Service Unavailable. Please try again later.'
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
