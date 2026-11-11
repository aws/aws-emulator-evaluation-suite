"""resource-policy-invalid-document-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-invalid-document-rejected"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with an empty Statement list is InvalidArgument (not IllegalUpdate) and
    persists nothing; a well-formed policy on the same resource then succeeds."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    vpc_origin_arn = _create_vpc_origin(ctx)
    ctx.on_cleanup(lambda: _try_delete_resource_policy(ctx, vpc_origin_arn))

    invalid_doc = {"Version": "2012-10-17", "Statement": []}
    code, message = _error(
        lambda: cf.put_resource_policy(
            ResourceArn=vpc_origin_arn, PolicyDocument=json.dumps(invalid_doc)
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for an empty-statement policy, got {code!r}"
    expected = "The specified policy format isn't valid. Verify that the format is valid JSON and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: a never-set policy reads as 200 with "{}"; EntityNotFound is also seen
    # after an explicit delete, so both count as absent.
    absent_doc = _policy_or_none(cf, vpc_origin_arn)
    assert absent_doc is None, (
        f"expected no resource policy to exist after the rejected Put, got {absent_doc!r}"
    )

    # positive control: a well-formed policy on the same resource still succeeds
    valid_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelf",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": vpc_origin_arn,
            }
        ],
    }
    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=json.dumps(valid_doc))
    got = json.loads(cf.get_resource_policy(ResourceArn=vpc_origin_arn)["PolicyDocument"])
    assert got == valid_doc, (
        f"expected the well-formed policy to round-trip unchanged after the earlier rejection, "
        f"got {got!r}"
    )


def _error(fn):
    """Call fn() and return its botocore (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _policy_or_none(cf, resource_arn):
    """The stored policy document, or None for EntityNotFound or a 200 with PolicyDocument "{}"."""
    from botocore.exceptions import ClientError

    try:
        resp = cf.get_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return None
    doc = json.loads(resp.get("PolicyDocument") or "{}")
    return doc or None


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
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_running(ec2, instance_id)
    return f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"


def _wait_instance_running(ec2, instance_id, timeout_s=120, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError:
            time.sleep(interval_s)
            continue
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} did not reach running within {timeout_s}s (last={state})")


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
        },
        Tags={"Items": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]},
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
