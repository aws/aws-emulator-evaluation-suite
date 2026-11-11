"""op-contract-modify-ipam-routing-policy-registration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-ipam-routing-policy-registration"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyIpamRoutingPolicyRegistration rejects a malformed internet registry association id with
    InvalidIpamInternetRegistryAssociationId.Malformed and its exact message, after
    DescribeIpamInternetRegistryAssociations succeeds as a positive control."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "modify_ipam_routing_policy_registration"):
        raise AssertionError("botocore in this environment lacks ModifyIpamRoutingPolicyRegistration")

    try:
        ec2.describe_ipam_internet_registry_associations()
    except ClientError as exc:
        raise AssertionError(
            "expected DescribeIpamInternetRegistryAssociations (no prerequisite) to succeed as a "
            f"positive control before testing the malformed-id rejection, got "
            f"{exc.response['Error']['Code']}"
        ) from exc

    code, message = _error(
        lambda: ec2.modify_ipam_routing_policy_registration(
            IpamInternetRegistryAssociationId="ipam-internet-reg-assoc-00000000000000000",
            Cidr="198.51.100.0/24",
            Asns=["64512"],
        )
    )
    assert code == "InvalidIpamInternetRegistryAssociationId.Malformed", (
        f"expected InvalidIpamInternetRegistryAssociationId.Malformed, got {code}"
    )
    assert message == (
        "The ipam-internet-registry-association ID "
        "'ipam-internet-reg-assoc-00000000000000000' is malformed"
    ), message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ModifyIpamRoutingPolicyRegistration to reject the malformed association id, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
