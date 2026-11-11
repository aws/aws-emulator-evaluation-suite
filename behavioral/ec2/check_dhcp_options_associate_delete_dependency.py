"""dhcp-options-associate-delete-dependency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

CHECK = "dhcp-options-associate-delete-dependency"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDhcpOptions/AssociateDhcpOptions/DeleteDhcpOptions dependency semantics."""
    ec2 = ctx.client("ec2")
    # A VPC of its own: the default VPC's DHCP options are account baseline and never changed.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dopt-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    original_dopt_id = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]

    resp = ec2.create_dhcp_options(
        DhcpConfigurations=[{"Key": "domain-name-servers", "Values": ["10.100.0.2"]}],
        TagSpecifications=[{"ResourceType": "dhcp-options", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    dopt_id = resp["DhcpOptions"]["DhcpOptionsId"]
    ctx.on_cleanup(lambda: _drop_dhcp_options(ec2, dopt_id, vpc_id))

    cfg = ec2.describe_dhcp_options(DhcpOptionsIds=[dopt_id])["DhcpOptions"][0]
    assert cfg["DhcpOptionsId"] == dopt_id, f"expected {dopt_id}, got {cfg}"

    ec2.associate_dhcp_options(DhcpOptionsId=dopt_id, VpcId=vpc_id)
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert vpc["DhcpOptionsId"] == dopt_id, f"association not reflected: {vpc}"

    # Must not be deletable while a VPC still references it.
    code, message = _error(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dopt_id))
    assert code == "DependencyViolation", (
        f"expected DependencyViolation deleting an associated DHCP option set, got {code}"
    )
    assert message == f"The dhcpOptions '{dopt_id}' has dependencies and cannot be deleted.", (
        f"unexpected DependencyViolation message: {message!r}"
    )

    # The rejected delete must have had no effect: the set is still there via an
    # independent read, and the VPC is still associated with it.
    survived = ec2.describe_dhcp_options(DhcpOptionsIds=[dopt_id])["DhcpOptions"][0]
    assert survived["DhcpOptionsId"] == dopt_id, (
        f"dhcp options set disappeared despite a rejected delete: {survived}"
    )
    still_vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert still_vpc["DhcpOptionsId"] == dopt_id, (
        f"VPC association changed despite a rejected delete: {still_vpc}"
    )

    # Restore the VPC's original DHCP options set by its id, then deletion of the set this
    # check created must succeed.
    ec2.associate_dhcp_options(DhcpOptionsId=original_dopt_id, VpcId=vpc_id)
    restored = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]
    assert restored == original_dopt_id, f"expected restore to {original_dopt_id}, got {restored}"

    ec2.delete_dhcp_options(DhcpOptionsId=dopt_id)

    gone, gone_message = _error(lambda: ec2.describe_dhcp_options(DhcpOptionsIds=[dopt_id]))
    assert gone == "InvalidDhcpOptionID.NotFound", (
        f"expected InvalidDhcpOptionID.NotFound, got {gone}"
    )
    assert gone_message == f"The dhcpOption ID '{dopt_id}' does not exist", (
        f"unexpected InvalidDhcpOptionID.NotFound message: {gone_message!r}"
    )


def _drop_dhcp_options(ec2, dopt_id, vpc_id):
    """Free the set from this check's VPC (a no-op once restored), then delete it if present."""
    ec2.associate_dhcp_options(DhcpOptionsId="default", VpcId=vpc_id)
    try:
        ec2.delete_dhcp_options(DhcpOptionsId=dopt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidDhcpOptionID.NotFound", "InvalidDhcpOptionsID.NotFound"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
