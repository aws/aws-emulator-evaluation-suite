"""create-default-vpc-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-default-vpc-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDefaultVpc in a region whose account baseline already holds the default VPC is
    rejected with DefaultVpcAlreadyExists and its exact message, and leaves that one default VPC
    as the sole default, unchanged."""
    ec2 = ctx.client("ec2")

    before = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    assert len(before) == 1, (
        f"the account baseline holds exactly one default VPC per region, but describe_vpcs found "
        f"{[v['VpcId'] for v in before]!r}"
    )
    baseline_id = before[0]["VpcId"]

    try:
        resp = ec2.create_default_vpc()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        created = resp["Vpc"]["VpcId"]
        if created != baseline_id:
            ctx.on_cleanup(lambda: _delete_vpc_and_subnets(ec2, created))
        raise AssertionError(
            f"CreateDefaultVpc SUCCEEDED while the default VPC {baseline_id!r} exists, "
            f"returning {resp['Vpc']!r}"
        )
    assert code == "DefaultVpcAlreadyExists", (
        f"unexpected CreateDefaultVpc rejection code {code!r} ({message})"
    )
    assert message == "A Default VPC already exists for this account in this region.", (
        f"unexpected error message {message!r}"
    )

    # Independent read: the rejected call must not have left a second default VPC behind, and the
    # baseline one must still be the sole default.
    after = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    assert [v["VpcId"] for v in after] == [baseline_id], (
        f"expected the default VPC to stay exactly {baseline_id!r} after the rejected call, found "
        f"{[v['VpcId'] for v in after]!r}"
    )


# ===== helpers =====
def _delete_vpc_and_subnets(ec2, vpc_id):
    for subnet in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
        ec2.delete_subnet(SubnetId=subnet["SubnetId"])
    ec2.delete_vpc(VpcId=vpc_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
