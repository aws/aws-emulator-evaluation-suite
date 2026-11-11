"""list-distributions-by-realtime-log-config-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-distributions-by-realtime-log-config-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByRealtimeLogConfig returns only the distribution whose default cache
    behavior is wired to a given real-time log config, not an unrelated control distribution
    that has no real-time log config attached."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    log_name = ctx.unique_name("sim2real-rtlog-")
    role_arn = f"arn:aws:iam::{account_id}:role/{log_name}-role"
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{log_name}-stream"
    log_config = cf.create_realtime_log_config(
        Name=log_name,
        EndPoints=[
            {
                "StreamType": "Kinesis",
                "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn},
            }
        ],
        Fields=["timestamp", "c-ip", "sc-status"],
        SamplingRate=100,
    )["RealtimeLogConfig"]
    log_arn = log_config["ARN"]
    ctx.on_cleanup(lambda: cf.delete_realtime_log_config(ARN=log_arn))

    wired_id = _create_distribution(
        ctx, cf, ctx.unique_name("sim2real-rtlog-wired-"), RealtimeLogConfigArn=log_arn
    )
    control_id = _create_distribution(ctx, cf, ctx.unique_name("sim2real-rtlog-ctrl-"))

    resp = cf.list_distributions_by_realtime_log_config(RealtimeLogConfigArn=log_arn)
    ids = {item["Id"] for item in resp["DistributionList"].get("Items", [])}
    assert wired_id in ids, f"expected wired distribution {wired_id} in {ids}"
    assert control_id not in ids, f"control distribution {control_id} unexpectedly in {ids}"


def _create_distribution(ctx, cf, ref: str, **default_cache_behavior_overrides) -> str:
    ref = ref.lower()
    origin_id = "origin1"
    default_cache_behavior = {
        "TargetOriginId": origin_id,
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": _MANAGED_CACHING_DISABLED_POLICY_ID,
    }
    default_cache_behavior.update(default_cache_behavior_overrides)
    config = {
        "CallerReference": ref,
        "Comment": "sim2real-behav cloudfront check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{ref}.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": default_cache_behavior,
    }
    dist_id = cf.create_distribution(DistributionConfig=config)["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _delete_distribution(cf, dist_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
