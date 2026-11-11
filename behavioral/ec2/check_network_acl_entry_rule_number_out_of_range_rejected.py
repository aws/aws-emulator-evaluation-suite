"""network-acl-entry-rule-number-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-acl-entry-rule-number-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAclEntry rejects a rule number outside the valid 1-32766 range --
    a quota/range boundary distinct from a not-found check."""
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.84.0.0/16",
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
            RuleNumber=40000,  # valid range is 1-32766
            Protocol="6",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
            PortRange={"From": 80, "To": 80},
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Value (40000) for parameter ruleNumber is invalid. Rulenumber must be in range 1..32766", message

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    assert not any(e["RuleNumber"] == 40000 for e in entries), (
        f"rejected RuleNumber 40000 must not appear in the ACL's entries, got {entries!r}"
    )

    # Positive control: a valid rule number on the same ACL succeeds, proving the
    # entry-creation path itself works and the rejection above is specific to the
    # out-of-range value rather than the account/credentials being broadly broken.
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="0.0.0.0/0",
        PortRange={"From": 80, "To": 80},
    )
    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    assert any(e["RuleNumber"] == 100 for e in entries), (
        f"positive control RuleNumber 100 must appear in the ACL's entries, got {entries!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_with_retry(ec2, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """create_vpc, retrying on VpcLimitExceeded.

    The default per-region VPC quota is shared with every other concurrently
    running behavioral check in this account; a burst of sibling checks can
    transiently exhaust it even though each check deletes its own VPC on
    teardown. Retry with backoff until a slot frees up rather than failing on a
    momentary quota collision.
    """
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
