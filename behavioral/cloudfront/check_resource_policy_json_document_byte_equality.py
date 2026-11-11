"""resource-policy-json-document-byte-equality."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "resource-policy-json-document-byte-equality"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A VPC-origin resource policy put with unusual whitespace reads back from GetResourcePolicy as the same
    document (Sid, Effect, Principal, Resource unchanged), except that the single-item Action list reads back
    as the bare string "cloudfront:GetVpcOrigin"."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    vpc_origin_arn = _create_vpc_origin(ctx)
    ctx.on_cleanup(lambda: _try_delete_resource_policy(ctx, vpc_origin_arn))

    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realByteEquality",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["cloudfront:GetVpcOrigin"],
                "Resource": vpc_origin_arn,
            }
        ],
    }
    # deliberately unusual (but valid) whitespace/formatting on the way in
    submitted_text = json.dumps(doc, indent=3, separators=(",", " : "))
    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=submitted_text)

    returned_text = cf.get_resource_policy(ResourceArn=vpc_origin_arn)["PolicyDocument"]
    returned_doc = json.loads(returned_text)

    expected = {**doc, "Statement": [{**doc["Statement"][0], "Action": "cloudfront:GetVpcOrigin"}]}
    assert returned_doc == expected, f"resource policy document was not preserved: {returned_doc!r} != {expected!r}"
    statement = returned_doc["Statement"][0]
    assert statement["Sid"] == "sim2realByteEquality", f"Sid not preserved: {statement['Sid']!r}"
    assert statement["Action"] == "cloudfront:GetVpcOrigin", (
        f"expected the single-item Action list to read back as a bare string, got {statement['Action']!r}"
    )
    assert statement["Principal"] == {"AWS": f"arn:aws:iam::{account_id}:root"}, (
        f"Principal not preserved: {statement['Principal']!r}"
    )


def _try_delete_resource_policy(ctx, resource_arn):
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        cf.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _create_probe_instance_arn(ctx):
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-vpco-probe-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=ctx.network().subnet_ids[0],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"


def _create_vpc_origin(ctx, timeout_s=900, interval_s=15):
    cf = ctx.client("cloudfront")
    instance_arn = _create_probe_instance_arn(ctx)
    name = ctx.unique_name("sim2real-vpco-")
    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": instance_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
        }
    )
    vpc_origin_id = resp["VpcOrigin"]["Id"]
    vpc_origin_arn = resp["VpcOrigin"]["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vpc_origin_id))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        g = cf.get_vpc_origin(Id=vpc_origin_id)
        if g["VpcOrigin"]["Status"] == "Deployed":
            break
        time.sleep(interval_s)
    else:
        raise AssertionError("VPC origin never reached Deployed status")
    return vpc_origin_arn


def _delete_vpc_origin(ctx, vpc_origin_id, timeout_s=900, interval_s=15):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        g = cf.get_vpc_origin(Id=vpc_origin_id)
        etag = g["ETag"]
        if g["VpcOrigin"]["Status"] == "Deployed":
            break
        time.sleep(interval_s)
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
