"""create-dhcp-options-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dhcp-options-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDhcpOptions persists the requested DHCP configuration verbatim,
    and rejects an option key that isn't one of the recognized DHCP option
    names.
    """
    ec2 = ctx.client("ec2")

    resp = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name-servers", "Values": ["AmazonProvidedDNS"]},
            {"Key": "domain-name", "Values": ["example.internal"]},
        ],
        TagSpecifications=[_tag_spec(ctx, "dhcp-options")],
    )
    options = resp["DhcpOptions"]
    options_id = options["DhcpOptionsId"]
    ctx.on_cleanup(lambda: ec2.delete_dhcp_options(DhcpOptionsId=options_id))

    configs = {c["Key"]: sorted(v["Value"] for v in c["Values"]) for c in options["DhcpConfigurations"]}
    assert configs.get("domain-name-servers") == ["AmazonProvidedDNS"], (
        f"expected domain-name-servers=['AmazonProvidedDNS'] on the create response, got {configs.get('domain-name-servers')!r}"
    )
    assert configs.get("domain-name") == ["example.internal"], (
        f"expected domain-name=['example.internal'] on the create response, got {configs.get('domain-name')!r}"
    )

    described = ec2.describe_dhcp_options(DhcpOptionsIds=[options_id])["DhcpOptions"][0]
    described_configs = {
        c["Key"]: sorted(v["Value"] for v in c["Values"]) for c in described["DhcpConfigurations"]
    }
    assert described_configs.get("domain-name-servers") == ["AmazonProvidedDNS"], (
        f"expected domain-name-servers=['AmazonProvidedDNS'] on the independent describe read, got {described_configs.get('domain-name-servers')!r}"
    )

    # Error boundary: an option key outside the fixed set of recognized DHCP
    # options must be rejected, not silently stored.
    code, message = _error_detail(
        lambda: ec2.create_dhcp_options(
            DhcpConfigurations=[{"Key": "not-a-real-dhcp-option", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message})"
    assert message == "Value (not-a-real-dhcp-option) for parameter name is invalid. Unknown DHCP option", f"unexpected error message {message!r}"


def _error_detail(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
