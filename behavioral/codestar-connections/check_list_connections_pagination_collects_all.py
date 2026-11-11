"""list-connections-pagination-collects-all."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connections-pagination-collects-all"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections with MaxResults=1 paginates via NextToken, and walking every page
    collects every connection created in this run exactly once.
    """
    cc = ctx.client("codestar-connections")
    conn_tags = [{"Key": "sim2real-env", "Value": "test"}]
    created = []
    for _ in range(3):
        arn = cc.create_connection(
            ConnectionName=ctx.unique_name("sim2real-pg-")[:32],
            ProviderType="GitHub",
            Tags=conn_tags,
        )["ConnectionArn"]
        ctx.on_cleanup(lambda arn=arn: _safe_delete_connection(cc, arn))
        created.append(arn)

    first_page = cc.list_connections(MaxResults=1)
    assert len(first_page["Connections"]) <= 1, (
        f"expected MaxResults=1 to cap the first page at 1, got {len(first_page['Connections'])}"
    )
    assert "NextToken" in first_page and first_page["NextToken"], (
        "expected a NextToken on the first page since 3 connections exist and MaxResults=1"
    )

    seen: list[str] = []
    token = None
    for _ in range(200):  # bounded: generous upper bound on page count
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_connections(**kwargs)
        assert len(page["Connections"]) <= 1, (
            f"expected every page to honor MaxResults=1, got {len(page['Connections'])}"
        )
        seen.extend(c["ConnectionArn"] for c in page["Connections"])
        token = page.get("NextToken")
        if not token:
            break

    assert all(arn in seen for arn in created), (
        f"expected all created connections {created} to appear across pages, saw {seen}"
    )
    # no duplicates across pages for our own connections
    for arn in created:
        assert seen.count(arn) == 1, (
            f"expected {arn} to appear exactly once across pages, appeared {seen.count(arn)} times"
        )


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
