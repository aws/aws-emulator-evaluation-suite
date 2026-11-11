"""list-clusters-contains-created-cluster."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-clusters-contains-created-cluster"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusters includes a freshly created cluster's identifier and arn among its summaries."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "list-clusters-contains-created-cluster"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    found = None
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = dsql.list_clusters(**kwargs)
        for summary in page["clusters"]:
            if summary["identifier"] == identifier:
                found = summary
                break
        if found is not None:
            break
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert found is not None, f"{identifier} not found in ListClusters"
    assert found["arn"] == created["arn"], (
        f"expected ListClusters arn {created['arn']!r} for {identifier}, got {found['arn']!r}"
    )


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
