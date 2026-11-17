"""create-network-acl-entry-cidr-and-ipv6-cidr-mutually-exclusive-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-acl-entry-cidr-and-ipv6-cidr-mutually-exclusive-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAclEntry rejects an entry naming both CidrBlock and Ipv6CidrBlock, and
    the same entry with only Ipv6CidrBlock succeeds.
    """
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    acl_id = ec2.create_network_acl(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "network-acl", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-acl-")}]}
        ],
    )["NetworkAcl"]["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    code, message = _error(
        lambda: ec2.create_network_acl_entry(
            NetworkAclId=acl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
            Ipv6CidrBlock="::/0",
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected_message = "The parameter cidrBlock cannot be used with the parameter ipv6CidrBlock"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    assert not any(e["RuleNumber"] == 100 for e in entries), (
        f"rejected entry must not appear in the ACL's entries, got {entries!r}"
    )

    # positive control: the legal neighbour -- only Ipv6CidrBlock -- succeeds
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="-1",
        RuleAction="allow",
        Egress=False,
        Ipv6CidrBlock="::/0",
    )
    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    matching = [e for e in entries if e["RuleNumber"] == 100]
    assert matching and matching[0].get("Ipv6CidrBlock") == "::/0", (
        f"expected RuleNumber 100 with Ipv6CidrBlock '::/0', got {entries!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call that SUCCEEDS
    raises AssertionError: real AWS refuses it, so acceptance must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_with_retry(ec2, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """create_vpc, retrying on VpcLimitExceeded while a sibling check's VPC is still being torn
    down, rather than failing on a momentary quota collision."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
