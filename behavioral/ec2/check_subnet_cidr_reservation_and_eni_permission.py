"""subnet-cidr-reservation-and-eni-permission."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error_code(fn):
    """Call *fn*; return the AWS error code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")

def _delete_reservation(ec2, res_id):
    """The body deletes the reservation itself; a reservation already gone is not a leak."""
    try:
        ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=res_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidSubnetCidrReservationID.NotFound":
            raise

CHECK = "subnet-cidr-reservation-and-eni-permission"
GROUP = 'vpc-subnet'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSubnetCidrReservation records the reservation; ENI permission validates the ENI."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.105.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"VPC {vpc_id} never became available within 60s")

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.105.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    resp = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id, Cidr="10.105.1.16/28", ReservationType="explicit"
    )
    res = resp["SubnetCidrReservation"]
    res_id = res["SubnetCidrReservationId"]
    ctx.on_cleanup(lambda: _delete_reservation(ec2, res_id))
    assert res["Cidr"] == "10.105.1.16/28"
    assert res["ReservationType"] == "explicit"

    listed = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    all_res = listed.get("SubnetIpv4CidrReservations", [])
    assert any(r["SubnetCidrReservationId"] == res_id for r in all_res), (
        f"reservation not listed: {all_res}"
    )

    # A reservation outside the subnet range must be refused.
    bad = _error_code(
        lambda: ec2.create_subnet_cidr_reservation(
            SubnetId=subnet_id, Cidr="10.200.0.0/28", ReservationType="explicit"
        )
    )
    assert bad == "InvalidParameterValue", (
        f"expected InvalidParameterValue for an out-of-range reservation, got {bad}"
    )

    deleted = ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=res_id)
    assert deleted["DeletedSubnetCidrReservation"]["SubnetCidrReservationId"] == res_id, (
        f"delete response should echo the deleted reservation id, got {deleted}"
    )
    after_delete = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)
    remaining_ids = {
        r["SubnetCidrReservationId"] for r in after_delete.get("SubnetIpv4CidrReservations", [])
    }
    assert res_id not in remaining_ids, f"deleted reservation still listed: {remaining_ids}"

    # Control: against a real ENI in the same subnet, CreateNetworkInterfacePermission gets past
    # the ENI lookup and is refused only for the grantee, which is not an AWS-authorized account.
    # Without this, the not-found boundary below cannot tell "rejects an unknown ENI id" from
    # "rejects every CreateNetworkInterfacePermission call".
    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    grantee_account = "111122223333"
    try:
        granted = ec2.create_network_interface_permission(
            NetworkInterfaceId=eni_id, AwsAccountId=grantee_account, Permission="INSTANCE-ATTACH",
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError(
            f"expected the grant to an unauthorized account to be refused, but it SUCCEEDED and "
            f"returned {granted!r}"
        )
    assert err.get("Code") == "OperationNotPermitted", (
        f"expected OperationNotPermitted for a real ENI and an unauthorized grantee, got {err}"
    )
    assert err.get("Message") == (
        f"The account {grantee_account} is not permitted to receive cross account permissions."
    ), f"unexpected refusal message: {err.get('Message')!r}"

    # CreateNetworkInterfacePermission must validate the ENI id.
    perm = _error_code(
        lambda: ec2.create_network_interface_permission(
            NetworkInterfaceId="eni-0123456789abcdef0",
            AwsAccountId=grantee_account,
            Permission="INSTANCE-ATTACH",
        )
    )
    assert perm == "InvalidNetworkInterfaceID.NotFound", (
        f"expected InvalidNetworkInterfaceID.NotFound, got {perm}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
