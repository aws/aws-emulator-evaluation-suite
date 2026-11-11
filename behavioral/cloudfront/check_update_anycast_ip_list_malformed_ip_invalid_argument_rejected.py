"""update-anycast-ip-list-malformed-ip-invalid-argument-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-anycast-ip-list-malformed-ip-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAnycastIpList resolves its target before validating the body.

    A nonexistent Id returns EntityNotFound for both a malformed and a well-formed CIDR body.
    """
    cf = ctx.client("cloudfront")

    # Positive control: Anycast IP lists need a quota increase to create, so a plain list
    # call shows the feature is reachable and the EntityNotFound results are not blanket failures.
    listed = cf.list_anycast_ip_lists()
    assert "Items" in listed["AnycastIpLists"], listed

    wellformed_missing_id = "IAL1A2B3C4D5E6"
    malformed_cidr_configs = [
        {
            "Cidr": "300.1.1.0/24",  # invalid octet -- not a parseable CIDR
            "IpamPoolArn": "arn:aws:ec2:us-east-1:123456789012:ipam-pool/ipam-pool-0123456789abcdef0",
        }
    ]
    c_malformed_body = _error_code(
        lambda: cf.update_anycast_ip_list(
            Id=wellformed_missing_id, IfMatch="ETVPDKIKX0DER", IpamCidrConfigs=malformed_cidr_configs
        )
    )
    assert c_malformed_body == "EntityNotFound", c_malformed_body

    # A well-formed body hits the same existence-check failure.
    c_valid_body = _error_code(
        lambda: cf.update_anycast_ip_list(Id=wellformed_missing_id, IfMatch="ETVPDKIKX0DER", IpAddressType="ipv4")
    )
    assert c_valid_body == "EntityNotFound", c_valid_body


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
