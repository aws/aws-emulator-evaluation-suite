"""list-connections-provider-type-filter-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connections-provider-type-filter-matches"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections ProviderTypeFilter returns only connections of that provider type."""
    cc = ctx.client("codestar-connections")

    github_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-gh-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, github_arn))

    bitbucket_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-bb-")[:32],
        ProviderType="Bitbucket",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, bitbucket_arn))

    filtered = cc.list_connections(ProviderTypeFilter="GitHub")["Connections"]
    arns = {c["ConnectionArn"] for c in filtered}
    assert github_arn in arns, f"expected {github_arn} in GitHub-filtered results {arns}"
    assert bitbucket_arn not in arns, f"Bitbucket connection {bitbucket_arn} leaked into GitHub filter {arns}"
    assert all(c["ProviderType"] == "GitHub" for c in filtered if c["ConnectionArn"] == github_arn), (
        f"GitHub-filtered entry for {github_arn} reported a non-GitHub ProviderType: {filtered}"
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
