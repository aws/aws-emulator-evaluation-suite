"""query-log-config-destination-arn-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-log-config-destination-arn-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s; last observed value: {last!r}")


def _error_code(fn):
    """Call fn(); return botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _delete_if_present(fn):
    """Run a teardown delete; ResourceNotFoundException (already gone) is fine, all else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DestinationArn of a log group with a mixed-case name is echoed unchanged, byte-for-byte,
    by CreateResolverQueryLogConfig and GetResolverQueryLogConfig: no re-casing or normalization."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    r53 = ctx.client("route53resolver")

    log_group_name = ctx.unique_name("Sim2Real-QlcMixedCase-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _delete_if_present(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    account_id = sts.get_caller_identity()["Account"]
    destination_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    create_resp = r53.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlc-"),
        DestinationArn=destination_arn,
        CreatorRequestId=ctx.unique_name("cr-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    config = create_resp["ResolverQueryLogConfig"]
    config_id = config["Id"]
    ctx.on_cleanup(
        lambda: _delete_if_present(lambda: r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))
    )

    assert config["DestinationArn"] == destination_arn, (
        f"CreateResolverQueryLogConfig echoed a different DestinationArn: "
        f"sent {destination_arn!r}, got {config['DestinationArn']!r}"
    )

    def get_config():
        return r53.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)["ResolverQueryLogConfig"]

    final = _poll_until(get_config, lambda c: c["Status"] in ("CREATED", "FAILED"), timeout_s=90.0, interval_s=3.0)
    assert final["Status"] == "CREATED", f"query log config did not reach CREATED, got {final['Status']!r}"
    assert final["DestinationArn"] == destination_arn, (
        f"GetResolverQueryLogConfig returned a mutated DestinationArn: "
        f"sent {destination_arn!r}, got {final['DestinationArn']!r}"
    )

    r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)

    def gone_code():
        return _error_code(lambda: r53.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id))

    _poll_until(gone_code, lambda code: code == "ResourceNotFoundException", timeout_s=60.0, interval_s=2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
