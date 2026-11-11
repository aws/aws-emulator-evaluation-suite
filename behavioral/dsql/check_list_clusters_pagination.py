"""list-clusters-pagination."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-clusters-pagination"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusters with maxResults=1 pages through nextToken and surfaces every created
    cluster exactly once, across page boundaries."""
    dsql = ctx.client("dsql")
    identifiers = set()
    for _ in range(3):
        created = dsql.create_cluster(
            deletionProtectionEnabled=False,
            tags={"sim2real-created-with": "list-clusters-pagination"},
        )
        identifier = created["identifier"]
        identifiers.add(identifier)
        ctx.on_cleanup(lambda cid=identifier: _best_effort_delete(dsql, cid))

    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = dsql.list_clusters(**kwargs)
        assert len(page["clusters"]) <= 1, (
            f"maxResults=1 must cap each page at 1 item; page {pages} returned "
            f"{len(page['clusters'])}"
        )
        seen.extend(c["identifier"] for c in page["clusters"])
        pages += 1
        next_token = page.get("nextToken")
        if not next_token or pages > 500:
            break

    assert identifiers.issubset(set(seen)), (
        f"expected all created clusters in paged listing; missing={identifiers - set(seen)}"
    )
    assert len(seen) == len(set(seen)), "ListClusters paged results must not repeat an identifier"
    assert pages >= len(identifiers), (
        f"expected at least one page per created cluster with maxResults=1; "
        f"pages={pages} created={len(identifiers)}"
    )


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
