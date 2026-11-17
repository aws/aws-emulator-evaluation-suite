"""network-acl-entry-malformed-ipv6-cidr-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-acl-entry-malformed-ipv6-cidr-rejected"
GROUP = "vpc-networking"
SERVICES = ["ec2"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAclEntry rejects an Ipv6CidrBlock with a prefix length past /128, and the
    network ACL stays unchanged; a well-formed Ipv6CidrBlock at the same rule number succeeds.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id

    acl = ec2.create_network_acl(
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "network-acl",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nacl-")}],
            }
        ],
    )["NetworkAcl"]
    acl_id = acl["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    code, message = _error(
        lambda: ec2.create_network_acl_entry(
            NetworkAclId=acl_id,
            RuleNumber=120,
            Protocol="6",
            RuleAction="allow",
            Egress=False,
            Ipv6CidrBlock="2001:db8::/129",
            PortRange={"From": 443, "To": 443},
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code} ({message!r})"
    expected_message = "CIDR block 2001:db8::/129 is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    assert not any(e["RuleNumber"] == 120 for e in entries), (
        f"the rejected entry must not appear: {entries}"
    )

    # The legal neighbour (a well-formed Ipv6CidrBlock, same rule number) succeeds.
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=120,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        Ipv6CidrBlock="2001:db8::/32",  # RFC 3849 documentation prefix
        PortRange={"From": 443, "To": 443},
    )
    # DescribeNetworkAcls is eventually consistent: poll until the control entry is visible
    # rather than asserting on a single, possibly-stale read.
    entries_after = _poll_until(
        lambda: ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"],
        lambda es: any(e["RuleNumber"] == 120 and not e["Egress"] for e in es),
        timeout_s=30.0,
    )
    accepted = next(e for e in entries_after if e["RuleNumber"] == 120 and not e["Egress"])
    assert accepted.get("Ipv6CidrBlock") == "2001:db8::/32", (
        f"expected Ipv6CidrBlock '2001:db8::/32', got {accepted.get('Ipv6CidrBlock')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
