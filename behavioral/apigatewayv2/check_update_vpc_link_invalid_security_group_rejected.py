"""update-vpc-link-invalid-security-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-vpc-link-invalid-security-group-rejected"
GROUP = "negative-classes"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed security group id fails CreateVpcLink with BadRequestException and creates no
    link; UpdateVpcLink with an empty name is rejected and leaves the link unchanged; a valid
    rename still applies."""
    apigwv2 = ctx.client("apigatewayv2")
    subnet_ids, security_group_ids = _pick_vpc_link_network(ctx)

    # UpdateVpcLink's schema only accepts `name` -- security groups/subnets cannot be changed
    # after creation, so the malformed-security-group boundary is exercised at CreateVpcLink time.
    bad_name = ctx.unique_name("sim2real-vpclink-badsg-")
    code, _ = _error_code(
        lambda: apigwv2.create_vpc_link(
            Name=bad_name,
            SubnetIds=subnet_ids,
            SecurityGroupIds=["not-a-valid-security-group-id"],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for a malformed security group id, got {code!r}"
    # message varies: it embeds the request id of the EC2 call API Gateway makes on the caller's behalf
    listing = apigwv2.get_vpc_links()["Items"]
    assert not any(v["Name"] == bad_name for v in listing), f"rejected CreateVpcLink {bad_name!r} must not have created a VpcLink"

    # positive control: a real security group id is accepted, so the rejection above is specific.
    name = ctx.unique_name("sim2real-vpclink-")
    created = apigwv2.create_vpc_link(Name=name, SubnetIds=subnet_ids, SecurityGroupIds=security_group_ids)
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link(apigwv2, vpc_link_id))
    assert sorted(created.get("SecurityGroupIds", [])) == sorted(security_group_ids), (
        f"expected the valid VpcLink to carry SecurityGroupIds {security_group_ids!r}, got {created.get('SecurityGroupIds')!r}"
    )

    before = apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)

    code, message = _error_code(
        lambda: apigwv2.update_vpc_link(VpcLinkId=vpc_link_id, Name="")
    )
    assert code == "BadRequestException", f"expected BadRequestException for an empty UpdateVpcLink name, got {code!r}"
    expected_message = "Vpc link name should not be null or empty."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    after_failed = apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)
    assert after_failed["Name"] == before["Name"], (
        f"a rejected UpdateVpcLink must leave Name unchanged: before={before['Name']!r} after={after_failed['Name']!r}"
    )
    assert sorted(after_failed.get("SecurityGroupIds", [])) == sorted(before.get("SecurityGroupIds", [])), (
        f"a rejected UpdateVpcLink must leave SecurityGroupIds unchanged: before={before.get('SecurityGroupIds')!r} "
        f"after={after_failed.get('SecurityGroupIds')!r}"
    )

    # positive control: a valid update (rename) still applies to the same link.
    new_name = ctx.unique_name("sim2real-vpclink-renamed-")
    apigwv2.update_vpc_link(VpcLinkId=vpc_link_id, Name=new_name)
    after_valid = apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)
    assert after_valid["Name"] == new_name, f"expected the valid rename to apply, got Name={after_valid['Name']!r}"



def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_vpc_link(apigw, vpc_link_id: str, timeout_s: float = 900.0) -> None:
    """A VPC link cannot be deleted while PENDING: wait it out, delete, then wait until the
    link reads NotFound."""
    import time

    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            status = apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if not deleted and status not in ("PENDING", "DELETING"):
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
            deleted = True
        time.sleep(10)
    raise AssertionError(f"VPC link {vpc_link_id} was not deleted within {timeout_s}s")


def _by_vpc_by_az(subnets):
    by_vpc = {}
    for s in subnets:
        by_vpc.setdefault(s["VpcId"], {}).setdefault(s["AvailabilityZone"], s)
    return by_vpc


def _pick_vpc_link_network(ctx, count=2):
    # CreateVpcLink requires every SubnetId to belong to the same VPC, so the fallback below
    # keeps the chosen subnets inside a single VPC.
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_vpc = _by_vpc_by_az(resp.get("Subnets", []))
    best_vpc = max(by_vpc, key=lambda v: len(by_vpc[v]), default=None)
    if best_vpc is None or len(by_vpc[best_vpc]) < count:
        raise AssertionError(
            f"no single VPC in this account/region has {count} subnets across distinct AZs; "
            "cannot provision a VpcLink to exercise UpdateVpcLink"
        )
    chosen = list(by_vpc[best_vpc].values())[:count]
    subnet_ids = [s["SubnetId"] for s in chosen]
    sg_resp = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [best_vpc]}, {"Name": "group-name", "Values": ["default"]}]
    )
    security_group_ids = [g["GroupId"] for g in sg_resp.get("SecurityGroups", [])][:1]
    if not security_group_ids:
        raise AssertionError(f"VPC {best_vpc!r} has no default security group to use as a valid positive control")
    return subnet_ids, security_group_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
