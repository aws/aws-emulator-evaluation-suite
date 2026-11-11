"""op-contract-replace-route-table-association."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-route-table-association"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceRouteTableAssociation moves a subnet to another route table under a new association
    id; an unknown association ID is rejected with InvalidAssociationID.NotFound and its message."""
    ec2 = ctx.client("ec2")

    # A VPC and subnet of its own: re-associating a default subnet's route table would change
    # account baseline that concurrent checks route through.
    vpc_id = _poll_until_success(
        lambda: ec2.create_vpc(CidrBlock="10.78.0.0/16",
                                TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rrta-")))["Vpc"]["VpcId"],
        retryable_codes={"VpcLimitExceeded"}, timeout_s=120, interval_s=10)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.78.1.0/24",
        TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-rrta-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    rt1_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tags("route-table", ctx.unique_name("sim2real-rrta-1-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt1_id))

    rt2_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tags("route-table", ctx.unique_name("sim2real-rrta-2-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt2_id))

    assoc_id = ec2.associate_route_table(RouteTableId=rt1_id, SubnetId=subnet_id)["AssociationId"]

    resp = ec2.replace_route_table_association(AssociationId=assoc_id, RouteTableId=rt2_id)
    new_assoc_id = resp["NewAssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=new_assoc_id))
    assert new_assoc_id and new_assoc_id != assoc_id, (
        f"expected a fresh association id distinct from {assoc_id!r}, got {new_assoc_id!r}")

    refreshed = ec2.describe_route_tables(RouteTableIds=[rt2_id])["RouteTables"][0]
    matches = [a for a in refreshed["Associations"] if a.get("SubnetId") == subnet_id]
    assert len(matches) == 1, "subnet is not associated with the new route table"
    assert matches[0]["RouteTableAssociationId"] == new_assoc_id, (
        f"expected association id {new_assoc_id!r}, got {matches[0]['RouteTableAssociationId']!r}")

    # Route-table association ids use the 8-hex-char format; a 17-char id is rejected as
    # InvalidAssociationID.Malformed before the existence check. Association resources share
    # the generic InvalidAssociationID.NotFound code.
    code, message = _error(lambda: ec2.replace_route_table_association(
        AssociationId="rtbassoc-12345678", RouteTableId=rt2_id))
    assert code == "InvalidAssociationID.NotFound", (
        f"expected InvalidAssociationID.NotFound, got {code}")
    assert message == "The association ID 'rtbassoc-12345678' does not exist", (
        f"unexpected InvalidAssociationID.NotFound message {message!r}")


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises."""
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
