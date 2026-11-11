"""op-contract-replace-network-acl-entry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-network-acl-entry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceNetworkAclEntry overwrites an existing rule in place (RuleAction
    flips allow->deny for the same rule number), and rejects an unknown NACL."""
    ec2 = ctx.client("ec2")

    # Reuse the run network's VPC when it is the default VPC; otherwise create a VPC (retrying VpcLimitExceeded).
    vpc_id = _get_default_vpc(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _poll_until_success(
            lambda: ec2.create_vpc(CidrBlock="10.76.0.0/16",
                                    TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rnae-")))["Vpc"]["VpcId"],
            retryable_codes={"VpcLimitExceeded"}, timeout_s=120, interval_s=10)
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    acl_id = ec2.create_network_acl(
        VpcId=vpc_id, TagSpecifications=_tags("network-acl", ctx.unique_name("sim2real-rnae-")),
    )["NetworkAcl"]["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))

    ec2.create_network_acl_entry(
        NetworkAclId=acl_id, RuleNumber=100, Protocol="6", RuleAction="allow", Egress=False,
        CidrBlock="10.0.0.0/16", PortRange={"From": 80, "To": 80},
    )

    ec2.replace_network_acl_entry(
        NetworkAclId=acl_id, RuleNumber=100, Protocol="6", RuleAction="deny", Egress=False,
        CidrBlock="10.0.0.0/16", PortRange={"From": 80, "To": 80},
    )

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    matches = [e for e in entries if e["RuleNumber"] == 100 and not e["Egress"]]
    assert len(matches) == 1, "expected exactly one rule 100 ingress entry"
    assert matches[0]["RuleAction"] == "deny", f"rule action was not replaced: {matches[0]}"
    assert matches[0]["CidrBlock"] == "10.0.0.0/16", f"cidr block changed unexpectedly: {matches[0]}"

    # Use a genuinely unassigned NACL id rather than a fabricated one: a
    # fabricated id whose hex suffix happens to be the *wrong* length for
    # this account/region's current ID-length convention (short 8-hex-char
    # vs. long 17-hex-char ids) is rejected up front as
    # InvalidNetworkAclId.Malformed, before AWS ever reaches the existence
    # check we're actually probing. Sidestep that entirely by creating a real, correctly
    # formatted-for-this-account NACL and immediately deleting it, so we
    # have a well-formed id that is guaranteed not to exist.
    #
    # Note the error code's casing: like the other "classic" (pre-VPC-
    # peering-era) resource types (Vpc, Subnet, Ami, ...), the NotFound code
    # uses a fully-capitalized "ID" suffix -- InvalidNetworkAclID.NotFound
    # -- not the lowercase "Id" used by newer resource types (that lowercase
    # "Id" form is what shows up in the unrelated Malformed error above).
    throwaway_acl_id = ec2.create_network_acl(
        VpcId=vpc_id, TagSpecifications=_tags("network-acl", ctx.unique_name("sim2real-rnae-gone-")),
    )["NetworkAcl"]["NetworkAclId"]
    ec2.delete_network_acl(NetworkAclId=throwaway_acl_id)
    gone_code, gone_message = _error(lambda: ec2.describe_network_acls(NetworkAclIds=[throwaway_acl_id]))
    assert gone_code == "InvalidNetworkAclID.NotFound", (
        f"expected the deleted NACL to be independently gone, got {gone_code}"
    )
    gone = f"The networkAcl ID '{throwaway_acl_id}' does not exist"
    assert gone_message == gone, f"unexpected DescribeNetworkAcls message {gone_message!r}"
    code, message = _error(lambda: ec2.replace_network_acl_entry(
        NetworkAclId=throwaway_acl_id, RuleNumber=100, Protocol="6",
        RuleAction="deny", Egress=False, CidrBlock="10.0.0.0/16",
        PortRange={"From": 80, "To": 80},
    ))
    assert code == "InvalidNetworkAclID.NotFound", f"expected InvalidNetworkAclID.NotFound, got {code}"
    assert message == gone, f"unexpected ReplaceNetworkAclEntry message {message!r}"


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _get_default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    defaults = [v for v in vpcs if v.get("IsDefault")]
    return defaults[0]["VpcId"] if defaults else None


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until_success(fn, retryable_codes, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
