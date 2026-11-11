"""op-contract-get-managed-prefix-list-associations."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-managed-prefix-list-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetManagedPrefixListAssociations lists a security group that references the
    prefix list, and rejects an unknown prefix list id.
    """
    ec2 = ctx.client("ec2")

    pl_name = ctx.unique_name("sim2real-pl-")
    prefix_list = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        AddressFamily="IPv4",
        MaxEntries=5,
        Entries=[{"Cidr": "10.203.0.0/16", "Description": "sim2real"}],
        TagSpecifications=_ec2_tag_specs("prefix-list", pl_name),
    )["PrefixList"]
    pl_id = prefix_list["PrefixListId"]
    _wait_pl_state(ec2, pl_id, {"create-complete"})
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))

    # baseline: a freshly created prefix list has no associations yet, so a target
    # that reports every security group as "associated" regardless of state fails here.
    baseline = ec2.get_managed_prefix_list_associations(PrefixListId=pl_id)[
        "PrefixListAssociations"
    ]
    assert baseline == [], f"expected no associations before any reference, got {baseline!r}"

    # A dedicated VPC holds the security group that references the prefix list.
    vpc_name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.204.0.0/16",
        TagSpecifications=_ec2_tag_specs("vpc", vpc_name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    sg_name = ctx.unique_name("sim2real-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real association test",
        VpcId=vpc_id,
        TagSpecifications=_ec2_tag_specs("security-group", sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    ingress_perms = [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "PrefixListIds": [{"PrefixListId": pl_id}],
        }
    ]
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress_perms)

    # success-path contract: the security group shows up as an association.
    associations = _poll_until(
        lambda: ec2.get_managed_prefix_list_associations(PrefixListId=pl_id)[
            "PrefixListAssociations"
        ],
        lambda assocs: any(a["ResourceId"] == sg_id for a in assocs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert associations is not None, "security group never appeared as an association"

    # the read tracks real state, not a fixed answer: revoking the only rule that
    # references the prefix list must make the association disappear again.
    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=ingress_perms)
    after_revoke = _poll_until(
        lambda: ec2.get_managed_prefix_list_associations(PrefixListId=pl_id)[
            "PrefixListAssociations"
        ],
        lambda assocs: not any(a["ResourceId"] == sg_id for a in assocs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after_revoke is not None, "security group still shows as an association after revoke"

    # error boundary: a well-formed but nonexistent prefix list id is rejected distinctly.
    code = _error_code(
        lambda: ec2.get_managed_prefix_list_associations(PrefixListId="pl-00000000000000000")
    )
    _assert_invalid_id(code, "PrefixList")


def _wait_pl_state(ec2, pl_id, target_states, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        lists = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"]
        if lists:
            state = lists[0]["State"]
            if state in target_states:
                return state
            if state == "create-failed":
                raise AssertionError(f"prefix list {pl_id} entered create-failed")
        time.sleep(interval_s)
    raise AssertionError(f"prefix list {pl_id} never reached {target_states}, last state {state}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return None


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises directly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _assert_invalid_id(code, token):
    assert code.endswith(".NotFound") or code.endswith(".Malformed"), (
        f"expected a *.NotFound/*.Malformed error code, got {code!r}"
    )
    assert token.lower() in code.lower(), f"expected {token!r} referenced in code, got {code!r}"


def _ec2_tag_specs(resource_type: str, name: str) -> list[dict]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "sim2real-managed", "Value": "true"},
                {"Key": "Name", "Value": name},
            ],
        }
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
