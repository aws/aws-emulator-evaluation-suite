"""describe-domain-controllers-invalid-next-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-domain-controllers-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDomainControllers with a garbage NextToken fails with InvalidNextTokenException and AWS's
    exact message rather than being ignored, while the same call without a token returns a list."""
    ds = ctx.client("ds")
    directory_id = _create_directory(ctx)

    # Positive control: a normal, untokened call succeeds (even while the directory is
    # still coming up, domain controllers just haven't appeared yet).
    resp = ds.describe_domain_controllers(DirectoryId=directory_id)
    assert isinstance(resp["DomainControllers"], list), (
        f"expected a list (possibly empty) of domain controllers, got {resp['DomainControllers']!r}"
    )

    # Negative: a malformed pagination token is rejected with the specific code.
    code, message, request_id = _error(
        lambda: ds.describe_domain_controllers(DirectoryId=directory_id, NextToken="not-a-real-token")
    )
    assert code == "InvalidNextTokenException", f"unexpected code: {code}"
    expected_message = f"Invalid value passed for the NextToken parameter. : RequestId: {request_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises. ds
    embeds the response's own RequestId in the message. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response["Error"].get("Message"),
            e.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _create_directory(ctx):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Passw0rd!23",
        Edition="Standard",
        Description="sim2real behavioral check",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    )
    directory_id = resp["DirectoryId"]

    def _cleanup():
        # A pre-delete wait for a terminal stage cannot fit ctx.on_cleanup's 60s budget --
        # directory creation alone takes many minutes -- so it would guarantee the cleanup
        # thread is killed before delete_directory is ever called. Fire the delete directly
        # and best-effort; AWS accepts DeleteDirectory against a directory still coming up.
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup)
    return directory_id


def _get_or_create_shared_vpc(ctx):
    """Look up the suite's shared VPC by tag before creating one, so concurrent checks converge on a
    single VPC rather than each provisioning their own (and exceeding the per-region VPC quota). No single
    check deletes it; it persists across runs."""
    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": _SHARED_VPC_TAG_NAME},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError("failed to create or find the shared sim2real-ds VPC")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.90.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{_SHARED_VPC_TAG_NAME}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
