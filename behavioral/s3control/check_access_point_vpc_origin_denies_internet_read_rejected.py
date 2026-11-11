"""access-point-vpc-origin-denies-internet-read-rejected."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-point-vpc-origin-denies-internet-read-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An internet read through a VPC-origin access point is denied by an implicit resource-policy deny
    that an explicit Allow for AWS:* does not lift; an Internet-origin access point serves the object.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    bucket = ctx.unique_name("sim2real-behav-apvpc-")
    vpc_ap = ctx.unique_name("sim2real-behav-apvpc-")
    net_ap = ctx.unique_name("sim2real-behav-apnet-")

    vpcs = [v["VpcId"] for v in ec2.describe_vpcs(
        Filters=[{"Name": "state", "Values": ["available"]}])["Vpcs"]]
    assert vpcs, "no available VPC in this account to bind a VPC-origin access point to"
    vpc_id = sorted(vpcs)[0]

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="private.txt", Body=b"vpc-only")

    vpc_arn = s3c.create_access_point(
        AccountId=account, Name=vpc_ap, Bucket=bucket,
        VpcConfiguration={"VpcId": vpc_id},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["AccessPointArn"]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, vpc_ap))

    described = s3c.get_access_point(AccountId=account, Name=vpc_ap)
    assert described["NetworkOrigin"] == "VPC", (
        f"an access point created with VpcConfiguration reported NetworkOrigin "
        f"{described['NetworkOrigin']!r}, expected VPC"
    )
    assert described["VpcConfiguration"] == {"VpcId": vpc_id}, (
        f"GetAccessPoint echoed VpcConfiguration {described.get('VpcConfiguration')!r}"
    )
    # AWS advertises the same regional hostnames for both origins.
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", described["Endpoints"]["ipv4"]), (
        f"GetAccessPoint reported ipv4 endpoint {described['Endpoints']['ipv4']!r} for the "
        "VPC-origin access point — AWS advertises the same regional hostnames as for an "
        "Internet-origin one, so the enforcement below cannot come from the endpoint set"
    )

    code, code_msg = _error(lambda: s3.get_object(Bucket=vpc_arn, Key="private.txt"))
    assert code == "AccessDenied", (
        f"an internet-borne read of a VPC-origin access point returned {code!r}, "
        "expected AccessDenied"
    )
    code_want = f"User: {caller} is not authorized to perform: s3:GetObject on resource: \"{vpc_arn}/object/private.txt\" with an explicit deny in a resource-based policy"
    assert code_msg == code_want, (
        f"the refusal carried message {code_msg!r}, expected {code_want!r}"
    )

    permissive = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"{vpc_arn}/object/*",
            }
        ],
    }
    s3c.put_access_point_policy(AccountId=account, Name=vpc_ap, Policy=json.dumps(permissive))
    ctx.on_cleanup(lambda: _drop_ap_policy(s3c, account, vpc_ap))
    still, still_msg = _error(lambda: s3.get_object(Bucket=vpc_arn, Key="private.txt"))
    assert still == "AccessDenied", (
        f"after an explicit Allow for Principal AWS:*, the internet read returned {still!r}; "
        "the VPC-origin deny must still win"
    )
    still_want = f"User: {caller} is not authorized to perform: s3:GetObject on resource: \"{vpc_arn}/object/private.txt\" with an explicit deny in a resource-based policy"
    assert still_msg == still_want, (
        f"the refusal carried message {still_msg!r}, expected {still_want!r}"
    )

    # Positive control: an Internet-origin access point over the same bucket serves it.
    net_arn = s3c.create_access_point(
        AccountId=account, Name=net_ap, Bucket=bucket,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["AccessPointArn"]
    ctx.on_cleanup(lambda: _drop_access_point(s3c, account, net_ap))
    body = s3.get_object(Bucket=net_arn, Key="private.txt")["Body"].read()
    assert body == b"vpc-only", (
        f"the Internet-origin control access point read returned {body!r}"
    )



def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _drop_ap_policy(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point_policy(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchAccessPointPolicy", "NoSuchAccessPoint"):
            raise


def _drop_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
