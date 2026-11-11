"""list-distributions-by-realtime-log-config-index-consistency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-realtime-log-config-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_kinesis_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-cf-rtlog-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    stream_arn = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )["StreamARN"]
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real:managed": "true"})
    return stream_arn


def _create_realtime_log_role(ctx, stream_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cf-rtlog-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kinesis:DescribeStreamSummary", "kinesis:PutRecords"],
                "Resource": stream_arn,
            }
        ],
    }
    policy_name = "sim2real-cf-rtlog-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_realtime_log_config(ctx, stream_arn, role_arn):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-rtlog-")

    def _attempt():
        # The IAM role/policy just created is eventually consistent; CloudFront can reject
        # it with InvalidArgument until the role is visible to it. Retry that specific error
        # on a deadline rather than sleeping blind before the first attempt.
        try:
            return cf.create_realtime_log_config(
                Name=name,
                EndPoints=[
                    {
                        "StreamType": "Kinesis",
                        "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn},
                    }
                ],
                Fields=["timestamp", "c-ip"],
                SamplingRate=100,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "InvalidArgument"):
                return None
            raise

    resp = _poll_until(_attempt, lambda r: r is not None, timeout_s=90.0, interval_s=5.0)
    config_arn = resp["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: cf.delete_realtime_log_config(ARN=config_arn))
    return config_arn


def _create_distribution(ctx, realtime_log_config_arn):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-"),
            "Comment": "sim2real behavioral check distribution",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "primary-origin",
                        "DomainName": origin_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "primary-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                "RealtimeLogConfigArn": realtime_log_config_arn,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
    return dist_id


def _list_by_realtime_log_config(cf, config_arn):
    ids = set()
    marker = None
    while True:
        kwargs = {"RealtimeLogConfigArn": config_arn, "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_realtime_log_config(**kwargs)
        dlist = resp["DistributionList"]
        ids.update(item["Id"] for item in dlist.get("Items", []))
        marker = dlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution configured with a realtime log config on its default cache behavior
    is enumerated by ListDistributionsByRealtimeLogConfig; removing the association removes
    it from the index."""
    cf = ctx.client("cloudfront")
    stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_realtime_log_role(ctx, stream_arn)
    config_arn = _create_realtime_log_config(ctx, stream_arn, role_arn)
    dist_id = _create_distribution(ctx, config_arn)

    ids_after_create = _poll_until(
        lambda: _list_by_realtime_log_config(cf, config_arn),
        lambda ids: dist_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id in ids_after_create, (
        f"distribution {dist_id!r} configured with realtime log config {config_arn!r} "
        f"never appeared in ListDistributionsByRealtimeLogConfig (got {ids_after_create!r})"
    )

    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    config["DefaultCacheBehavior"].pop("RealtimeLogConfigArn", None)
    cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=config_resp["ETag"])

    ids_after_remove = _poll_until(
        lambda: _list_by_realtime_log_config(cf, config_arn),
        lambda ids: dist_id not in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id not in ids_after_remove, (
        f"distribution {dist_id!r} still appeared in ListDistributionsByRealtimeLogConfig "
        f"for {config_arn!r} after the association was removed (got {ids_after_remove!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
