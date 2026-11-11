"""create-cluster-client-token-idempotency-and-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-client-token-idempotency-and-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying CreateCluster with the same clientToken and the same parameters is idempotent (no new
    cluster), but reusing that token with different parameters is rejected with ConflictException and
    creates nothing."""
    dsql = ctx.client("dsql")
    token = ctx.unique_name("sim2real-dsql-tok-")
    tags = {"sim2real-purpose": "idempotency-check"}

    first = dsql.create_cluster(clientToken=token, deletionProtectionEnabled=False, tags=tags)
    identifier = first["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    # Same token, same params -> idempotent replay returns the SAME cluster, not a new one.
    replay = dsql.create_cluster(clientToken=token, deletionProtectionEnabled=False, tags=tags)
    assert replay["identifier"] == identifier
    assert replay["arn"] == first["arn"]

    # Same token, different params -> rejected.
    code, message = _error(
        lambda: dsql.create_cluster(
            clientToken=token,
            deletionProtectionEnabled=False,
            tags={"sim2real-purpose": "different-value"},
        )
    )
    assert code == "ConflictException", code
    assert message == "Requests using a client token should supply identical request parameters", message

    # Effect absent: the original cluster's tags were never overwritten by the rejected call.
    got = dsql.get_cluster(identifier=identifier)
    assert got["tags"].get("sim2real-purpose") == "idempotency-check"

    # No extra cluster was created for this token: ListClusters shows exactly one cluster with this arn.
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = dsql.list_clusters(**kwargs)
        matches += sum(1 for c in page["clusters"] if c["arn"] == first["arn"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert matches == 1, f"expected exactly one cluster for this token, saw {matches}"


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
