"""delete-vpc-with-subnet-fails-dependency-violation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vpc-with-subnet-fails-dependency-violation"
GROUP = 'error-semantics'
SERVICES = ['ec2']
#: The default service-class budget for a poll; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpc while a subnet still exists in it must fail with DependencyViolation."""
    ec2 = ctx.client("ec2")
    run_tag = {"Key": "sim2real-check", "Value": ctx.unique_name("dvpc-")}
    tag_filter = [{"Name": f"tag:{run_tag['Key']}", "Values": [run_tag["Value"]]}]
    vpc_id = ec2.create_vpc(CidrBlock="10.2.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [run_tag]}])["Vpc"]["VpcId"]
    deleted_vpc = {"value": False}
    ctx.on_cleanup(lambda: None if deleted_vpc["value"] else ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"VPC not available after {POLL_BUDGET_S:.0f}s")
        time.sleep(2)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.2.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [run_tag]}])["Subnet"]["SubnetId"]
    deleted_subnet = {"value": False}
    ctx.on_cleanup(lambda: None if deleted_subnet["value"] else ec2.delete_subnet(SubnetId=subnet_id))

    refused = _error(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _assert_error(refused, "DependencyViolation", vpc_id)
    expected_message = f"The vpc '{vpc_id}' has dependencies and cannot be deleted."
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'

    # The rejected delete must have had no effect: an independent read still finds the VPC.
    still_there = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert len(still_there) == 1 and still_there[0]["VpcId"] == vpc_id, (
        f"expected {vpc_id} to survive the rejected delete, got {still_there!r}"
    )

    # Remove the dependency, then the identical call must now succeed (this is what tells a
    # correctly-enforcing target apart from one that rejects every DeleteVpc unconditionally).
    ec2.delete_subnet(SubnetId=subnet_id)
    deleted_subnet["value"] = True
    ec2.delete_vpc(VpcId=vpc_id)
    deleted_vpc["value"] = True

    # Gone beat 1: both by-id reads answer NotFound.
    _assert_error(_error(lambda: ec2.describe_subnets(SubnetIds=[subnet_id])), "InvalidSubnetID.NotFound", subnet_id)
    _assert_error(_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])), "InvalidVpcID.NotFound", vpc_id)
    # Gone beat 2: nothing carrying this run's tag is listed.
    left_vpcs = [v["VpcId"] for v in ec2.describe_vpcs(Filters=tag_filter)["Vpcs"]]
    left_subnets = [n["SubnetId"] for n in ec2.describe_subnets(Filters=tag_filter)["Subnets"]]
    assert not left_vpcs and not left_subnets, (
        f"deleted resources still listed by tag: vpcs={left_vpcs!r} subnets={left_subnets!r}"
    )
    # Gone beat 3: the dead ids are unusable. A second DeleteSubnet answers 400 on AWS; CreateSubnet's
    # status is graded 4xx.
    _assert_error(
        _error(lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.2.2.0/24")), "InvalidVpcID.NotFound", None, status=None
    )
    _assert_error(_error(lambda: ec2.delete_subnet(SubnetId=subnet_id)), "InvalidSubnetID.NotFound", None)


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _assert_error(resp, code, subject, status=400):
    """Grade a refusal on code + HTTP status (any 4xx when status is None) + the exact message
    (naming the subject if given)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    if status is None:
        assert isinstance(got_status, int) and 400 <= got_status < 500, f"expected a 4xx for {code}, got {got_status!r}"
    else:
        assert got_status == status, f"expected HTTP {status} for {code}, got {got_status!r}"
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"
    if subject is not None:
        assert subject in err["Message"], f"expected the {code} message to name {subject!r}, got {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
