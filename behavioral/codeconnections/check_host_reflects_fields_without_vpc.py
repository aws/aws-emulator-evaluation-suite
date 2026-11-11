"""host-reflects-fields-without-vpc."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-reflects-fields-without-vpc"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A host created without a VpcConfiguration reflects its Name/ProviderType/
    ProviderEndpoint on GetHost, carries no VpcConfiguration field, and remains
    PENDING (no VPC provisioning transitions apply to a non-VPC host)."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-host-")[:64]
    endpoint = "https://ghe-novpc.example.com"
    arn = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint=endpoint,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=arn))

    got = cc.get_host(HostArn=arn)
    assert got["Name"] == name, "actual_name=" + repr(got["Name"])
    assert got["ProviderType"] == "GitHubEnterpriseServer", (
        "actual_provider_type=" + repr(got["ProviderType"])
    )
    assert got["ProviderEndpoint"] == endpoint, (
        "actual_provider_endpoint=" + repr(got["ProviderEndpoint"])
    )
    assert got["Status"] == "PENDING", "actual_status=" + repr(got["Status"])
    assert "VpcConfiguration" not in got, (
        "actual_vpc_configuration=" + repr(got.get("VpcConfiguration"))
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
