"""list-connections-host-arn-filter-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connections-host-arn-filter-matches"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections HostArnFilter returns only connections bound to that host."""
    cc = ctx.client("codestar-connections")

    host_arn = cc.create_host(
        Name=ctx.unique_name("sim2real-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, host_arn))

    hosted_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-h-")[:32],
        HostArn=host_arn,
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, hosted_arn))

    plain_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-p-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, plain_arn))

    filtered = cc.list_connections(HostArnFilter=host_arn)["Connections"]
    arns = {c["ConnectionArn"] for c in filtered}
    assert hosted_arn in arns, f"expected {hosted_arn} (bound to host) in HostArnFilter result {arns}"
    assert plain_arn not in arns, f"expected {plain_arn} (no host) absent from HostArnFilter result {arns}"


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_host(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_host(HostArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
