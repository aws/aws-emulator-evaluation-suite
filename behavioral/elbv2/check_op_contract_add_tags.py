"""op-contract-add-tags."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-add-tags"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags attaches tags visible via DescribeTags; duplicate keys in one call are rejected."""
    vpc_id, _ = _default_vpc_and_subnets(ctx)
    tg = _create_tg(ctx, vpc_id)
    elbv2 = ctx.client("elbv2")

    resp = elbv2.add_tags(
        ResourceArns=[tg["TargetGroupArn"]],
        Tags=[{"Key": "Environment", "Value": "sim2real"}, {"Key": "Owner", "Value": "behavioral"}],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    described = elbv2.describe_tags(ResourceArns=[tg["TargetGroupArn"]])["TagDescriptions"]
    assert len(described) == 1
    tag_map = {t["Key"]: t["Value"] for t in described[0]["Tags"]}
    assert tag_map.get("Environment") == "sim2real"
    assert tag_map.get("Owner") == "behavioral"

    code, message = _error(
        lambda: elbv2.add_tags(
            ResourceArns=[tg["TargetGroupArn"]],
            Tags=[{"Key": "Dup", "Value": "1"}, {"Key": "Dup", "Value": "2"}],
        )
    )
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "DuplicateTagKeys", f"expected DuplicateTagKeys, got {code}"
    expected = "Tag key 'Dup' has two values, but tag keys must have exactly one value"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_reject = elbv2.describe_tags(ResourceArns=[tg["TargetGroupArn"]])["TagDescriptions"][0]["Tags"]
    after_map = {t["Key"]: t["Value"] for t in after_reject}
    assert "Dup" not in after_map, f"rejected duplicate-key AddTags must not apply anything, got {after_map}"
    assert after_map == {"Environment": "sim2real", "Owner": "behavioral"}, (
        f"tag set must be unchanged after the rejected call, got {after_map}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return vpc_id, list(by_az.values())


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
