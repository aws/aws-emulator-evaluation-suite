"""resource-policy-server-side-round-trip-enforcement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "resource-policy-server-side-round-trip-enforcement"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a VPC origin, GetResourcePolicy returns the put document unchanged, a second PutResourcePolicy replaces
    it, DeleteResourcePolicy reverts GetResourcePolicy to the pre-Put baseline, and a second delete succeeds as a
    no-op that leaves the baseline in place."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    vpc_origin_arn = _create_vpc_origin(ctx)

    # 1. capture whatever the pre-Put baseline actually is (either EntityNotFound, or some
    # default/absent-policy representation) -- CloudFront's exact "no policy set" shape is not
    # assumed, only that it round-trips back to the SAME shape after Delete (step 4).
    baseline_present, baseline_doc = _get_policy_or_none(cf, vpc_origin_arn)

    # 2. put, and it is immediately retrievable. PutResourcePolicy on a just-Deployed VPC origin can
    # answer InvalidArgument/InvalidPolicy for a while, so the put is retried on that answer only.
    doc_v1 = _policy_doc(account_id, vpc_origin_arn, sid="AllowV1", action="cloudfront:GetVpcOrigin")
    _put_resource_policy_with_retry(cf, vpc_origin_arn, doc_v1)
    ctx.on_cleanup(lambda: _try_delete_resource_policy(ctx, vpc_origin_arn))
    got_v1 = json.loads(cf.get_resource_policy(ResourceArn=vpc_origin_arn)["PolicyDocument"])
    assert got_v1 == doc_v1, "PutResourcePolicy document was not returned unchanged by GetResourcePolicy"

    # 3. a second put server-side replaces the document (not additive, not ignored)
    # A VPC-origin policy may grant only read actions on the origin, so the replacement differs
    # from the first document by its Sid.
    doc_v2 = _policy_doc(account_id, vpc_origin_arn, sid="AllowV2", action="cloudfront:GetVpcOrigin")
    _put_resource_policy_with_retry(cf, vpc_origin_arn, doc_v2)
    got_v2 = json.loads(cf.get_resource_policy(ResourceArn=vpc_origin_arn)["PolicyDocument"])
    assert got_v2 == doc_v2, "second PutResourcePolicy call was not enforced server-side"
    assert got_v2 != got_v1, "resource policy was not replaced by the second Put"

    # 4. delete removes it for good -- the resource reverts to the SAME baseline observed in step 1
    # DeleteResourcePolicy propagates asynchronously, so the read polls (bounded) for the baseline.
    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)
    after_present, after_doc = _poll_policy_until(
        cf, vpc_origin_arn, (baseline_present, baseline_doc), timeout_s=600.0
    )
    assert (after_present, after_doc) == (baseline_present, baseline_doc), (
        f"expected DeleteResourcePolicy to revert to the pre-Put baseline "
        f"(present={baseline_present!r}, doc={baseline_doc!r}), got "
        f"(present={after_present!r}, doc={after_doc!r})"
    )

    # 5. a second delete against the now-absent policy is an idempotent no-op on real AWS
    # (not EntityNotFound), and the resource stays at the baseline
    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)
    assert _get_policy_or_none(cf, vpc_origin_arn) == (baseline_present, baseline_doc), (
        "expected a second DeleteResourcePolicy to leave the pre-Put baseline in place"
    )


def _policy_doc(account_id, resource_arn, sid, action):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _get_policy_or_none(cf, resource_arn):
    """(present, doc) for a resource's policy -- doc is None both when GetResourcePolicy raises
    EntityNotFound AND (defensively) when it returns without a PolicyDocument, so callers compare
    a stable pair rather than assuming which shape CloudFront uses for "no policy set"."""
    from botocore.exceptions import ClientError

    try:
        resp = cf.get_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return False, None
    doc = resp.get("PolicyDocument")
    return True, json.loads(doc) if doc is not None else None


def _poll_policy_until(cf, resource_arn, want, timeout_s, interval_s=10.0):
    """Re-read the policy until it equals ``want`` or ``timeout_s`` passes; return the last read."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = _get_policy_or_none(cf, resource_arn)
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


def _put_resource_policy_with_retry(cf, resource_arn, doc, timeout_s=650.0, interval_s=15.0):
    """PutResourcePolicy, retried unchanged while a just-Deployed VPC origin answers InvalidArgument/InvalidPolicy
    (its Resource reported as not matching ResourceArn). Any other error, or that one past the deadline, raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cf.put_resource_policy(ResourceArn=resource_arn, PolicyDocument=json.dumps(doc))
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code in ("ServiceUnavailable", "InternalError", "Throttling") or (
                code == "InvalidArgument" and "InvalidPolicy" in message
            )
            if not transient:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


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
