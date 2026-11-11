"""resolver-query-log-config-destination-arn-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-query-log-config-destination-arn-preserved"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The DestinationArn supplied on CreateResolverQueryLogConfig -- including its region
    and account-id segments -- is returned unmodified on GetResolverQueryLogConfig."""
    logs = ctx.client("logs")
    r53r = ctx.client("route53resolver")

    log_group_name = ctx.unique_name("/sim2real/r53r-qlc-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    matches = [g for g in described if g["logGroupName"] == log_group_name]
    assert matches, f"log group {log_group_name!r} not found after creation"
    raw_arn = matches[0]["arn"]
    # CloudWatch Logs' DescribeLogGroups appends a ":*" wildcard suffix to the log-group ARN
    # it returns; that suffix is not part of the canonical resource ARN, so strip it before
    # handing the ARN to Resolver -- the round-trip we're checking is of the canonical ARN,
    # not of CloudWatch's display convention.
    destination_arn = raw_arn[:-2] if raw_arn.endswith(":*") else raw_arn
    # A CloudWatch Logs log group ARN carries region and account-id segments:
    # arn:aws:logs:<region>:<account-id>:log-group:<name>
    assert f":{ctx.region}:" in destination_arn, destination_arn

    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlc-")[:64],
        DestinationArn=destination_arn,
        CreatorRequestId=ctx.unique_name("sim2real-qlc-req-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))
    )
    assert config["DestinationArn"] == destination_arn, (
        f"CreateResolverQueryLogConfig echoed a mutated DestinationArn: "
        f"sent {destination_arn!r}, got {config['DestinationArn']!r}"
    )

    fetched = r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
        "ResolverQueryLogConfig"
    ]
    assert fetched["DestinationArn"] == destination_arn, (
        f"DestinationArn mutated: expected {destination_arn!r}, got {fetched['DestinationArn']!r}"
    )

    listed = r53r.list_resolver_query_log_configs()["ResolverQueryLogConfigs"]
    matches_listed = [c for c in listed if c["Id"] == config_id]
    assert len(matches_listed) == 1, (
        f"expected config {config_id!r} to appear exactly once in ListResolverQueryLogConfigs, "
        f"found {len(matches_listed)}"
    )
    assert matches_listed[0]["DestinationArn"] == destination_arn, (
        f"ListResolverQueryLogConfigs returned a mutated DestinationArn: "
        f"expected {destination_arn!r}, got {matches_listed[0]['DestinationArn']!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
