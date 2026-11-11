"""host-created-in-pending-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-created-in-pending-status"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHost always returns a host in PENDING status; it must be completed via the
    console ("Set up a pending host") before it can reach AVAILABLE."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-host-")[:64]
    endpoint = "https://ghe.example.com"
    resp = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint=endpoint,
        Tags=[{"Key": "sim2real-check", "Value": "host-created-in-pending-status"}],
    )
    arn = resp["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=arn))

    assert arn.startswith("arn:aws"), f"expected an arn:aws HostArn, got {arn!r}"
    assert "host/" in arn, f"expected a host/ resource segment in the ARN, got {arn!r}"

    got = cc.get_host(HostArn=arn)
    assert got["Name"] == name, f"expected Name={name!r}, got {got.get('Name')!r}"
    assert got["ProviderType"] == "GitHubEnterpriseServer", (
        f"expected ProviderType='GitHubEnterpriseServer', got {got.get('ProviderType')!r}"
    )
    assert got["ProviderEndpoint"] == endpoint, (
        f"expected ProviderEndpoint={endpoint!r}, got {got.get('ProviderEndpoint')!r}"
    )
    assert got["Status"] == "PENDING", (
        f"expected a freshly created host to be PENDING, got {got.get('Status')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
