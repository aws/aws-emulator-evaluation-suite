"""resolver-query-log-config-timestamp-precision-preserved."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "resolver-query-log-config-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-r53r"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """The CreationTime timestamp returned at CreateResolverQueryLogConfig is
    byte-identical when re-read via GetResolverQueryLogConfig and via
    ListResolverQueryLogConfigs."""
    r53r = ctx.client("route53resolver")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-r53r-lg-")
    logs.create_log_group(
        logGroupName=log_group_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-r53r"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    lg = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert len(lg) == 1, f"expected exactly one log group named {log_group_name!r}"
    destination_arn = lg[0]["arn"]

    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-r53r-qlc-"),
        DestinationArn=destination_arn,
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Tags=TAGS_KV,
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    created_time = config["CreationTime"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))

    fetched = r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
        "ResolverQueryLogConfig"
    ]
    assert fetched["CreationTime"] == created_time, (
        f"GetResolverQueryLogConfig CreationTime {fetched['CreationTime']!r} != "
        f"create-time value {created_time!r}"
    )

    listed = r53r.list_resolver_query_log_configs()["ResolverQueryLogConfigs"]
    matches = [c for c in listed if c["Id"] == config_id]
    assert len(matches) == 1, f"expected config {config_id!r} to appear exactly once in list"
    assert matches[0]["CreationTime"] == created_time, (
        f"ListResolverQueryLogConfigs CreationTime {matches[0]['CreationTime']!r} != "
        f"create-time value {created_time!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
