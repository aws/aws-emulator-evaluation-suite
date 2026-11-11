"""op-contract-describe-route-tables."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-route-tables"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRouteTables filtered by a new VPC's ID returns exactly its main route table with one active
    local route for the VPC CIDR, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    resp = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    tables = resp["RouteTables"]
    assert len(tables) == 1, f"expected exactly 1 (main) route table for a new VPC, got {len(tables)}"
    main_table = tables[0]
    assert main_table["VpcId"] == vpc_id
    assert main_table["RouteTableId"].startswith("rtb-")
    assert any(assoc.get("Main") is True for assoc in main_table["Associations"]), (
        f"expected a Main=True association, got {main_table['Associations']}"
    )
    local_routes = [r for r in main_table["Routes"] if r.get("GatewayId") == "local"]
    assert len(local_routes) == 1, f"expected exactly one local route, got {main_table['Routes']}"
    assert local_routes[0]["DestinationCidrBlock"] == "10.77.0.0/16"
    assert local_routes[0]["State"] == "active"

    code, msg = _client_error(lambda: ec2.describe_route_tables(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
