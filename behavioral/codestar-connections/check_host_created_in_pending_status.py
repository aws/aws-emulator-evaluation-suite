"""host-created-in-pending-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-created-in-pending-status"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GitHubEnterpriseServer host reads back with its name, provider type and endpoint and in PENDING status,
    since it needs a manual setup step to become AVAILABLE.
    """
    csc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-behav-host-")
    endpoint = "https://ghes.example.com"

    arn = csc.create_host(
        Name=name, ProviderType="GitHubEnterpriseServer", ProviderEndpoint=endpoint
    )["HostArn"]
    ctx.on_cleanup(lambda: csc.delete_host(HostArn=arn))

    host = csc.get_host(HostArn=arn)
    assert host["Name"] == name, f"expected Name {name!r}, got {host['Name']!r}"
    assert host["ProviderType"] == "GitHubEnterpriseServer", (
        f"expected ProviderType GitHubEnterpriseServer, got {host['ProviderType']!r}"
    )
    assert host["ProviderEndpoint"] == endpoint, (
        f"expected ProviderEndpoint {endpoint!r}, got {host['ProviderEndpoint']!r}"
    )
    assert host["Status"] == "PENDING", f"expected Status PENDING, got {host['Status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
