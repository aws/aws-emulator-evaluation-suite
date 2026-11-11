"""create-host-duplicate-names-allowed-distinct-arns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-host-duplicate-names-allowed-distinct-arns"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Host Name is not a unique key: two hosts may share the same Name, each getting its
    own independently addressable HostArn (mirrors the same non-uniqueness contract already
    established for ConnectionName, verified separately here for the Host resource type).
    """
    cc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-host-dupe-")
    tags = [{"Key": "sim2real-purpose", "Value": "behavioral-check"}]

    arn1 = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=tags,
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, arn1))

    arn2 = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=tags,
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, arn2))

    assert arn1 != arn2, f"two CreateHost calls with the same Name got the same HostArn: {arn1}"

    h1 = cc.get_host(HostArn=arn1)
    h2 = cc.get_host(HostArn=arn2)
    assert h1["Name"] == name, f"expected Name={name!r}, got {h1.get('Name')!r} for {arn1}"
    assert h2["Name"] == name, f"expected Name={name!r}, got {h2.get('Name')!r} for {arn2}"


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
