"""resolver-query-log-config-bad-destination-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-query-log-config-bad-destination-rejected"
GROUP = 'query-log-config'
SERVICES = ['route53resolver']


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_when_possible(fn, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is gone; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"teardown {fn.__name__}({kwargs}) never succeeded; last error {last}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _log_group_arn(ctx, account, name):
    """The ARN a CloudWatch Logs customer writes for a log group destination -- with the ``:*``
    stream wildcard CloudWatch Logs itself reports in ``describe_log_groups``."""
    return f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _stored_log_group_arn(ctx, account, name):
    """The form Resolver stores: DestinationArn with the trailing ``:*`` stream wildcard stripped.

    Both spellings of the log-group ARN come back in this single canonical form.
    """
    return f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}"


def _configs_named(r53, name):
    """Return query log configs whose Name matches, via the server-side filter."""
    resp = r53.list_resolver_query_log_configs(
        Filters=[{"Name": "Name", "Values": [name]}]
    )
    return resp


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolverQueryLogConfig for a nonexistent log group fails [RSLVR-01600] AccessDenied.
    No config is stored in any status, while a config for an existing log group is created with
    the canonical (wildcard-stripped) DestinationArn and stays findable by name.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverQueryLogConfig.html
    """
    r53 = ctx.client("route53resolver")
    logs = ctx.client("logs")
    account = _account_id(ctx)

    # A real destination for the control leg.
    good_lg = ctx.unique_name("sim2real-behav-r53r-lg-")
    logs.create_log_group(logGroupName=good_lg)
    ctx.on_cleanup(
        lambda n=good_lg: _delete_when_possible(logs.delete_log_group, logGroupName=n)
    )
    good_arn = _log_group_arn(ctx, account, good_lg)
    stored_arn = _stored_log_group_arn(ctx, account, good_lg)

    # CONTROL: a config pointing at a destination that exists is accepted and settles.
    good_name = ctx.unique_name("sim2real-behav-qlc-ok-")
    created = r53.create_resolver_query_log_config(
        Name=good_name,
        DestinationArn=good_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
    )["ResolverQueryLogConfig"]
    config_id = created["Id"]
    ctx.on_cleanup(
        lambda x=config_id: _delete_when_possible(
            r53.delete_resolver_query_log_config, ResolverQueryLogConfigId=x
        )
    )
    assert created["Name"] == good_name, created
    assert created["DestinationArn"] == stored_arn, (
        f"the config must store the destination as the canonical log-group ARN "
        f"{stored_arn!r} (the ``:*`` stream wildcard is stripped, not echoed), got "
        f"{created['DestinationArn']!r}"
    )
    assert created["Status"] in ("CREATING", "CREATED"), created

    # The wildcard-free ARN is accepted too and stores the identical string.
    bare_name = ctx.unique_name("sim2real-behav-qlc-bare-")
    bare = r53.create_resolver_query_log_config(
        Name=bare_name,
        DestinationArn=stored_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
    )["ResolverQueryLogConfig"]
    ctx.on_cleanup(
        lambda x=bare["Id"]: _delete_when_possible(
            r53.delete_resolver_query_log_config, ResolverQueryLogConfigId=x
        )
    )
    assert bare["DestinationArn"] == stored_arn, bare
    assert bare["Id"] != config_id, (
        f"two configs naming the same destination are distinct resources, got {bare!r}"
    )

    settled = _poll(
        lambda: r53.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
            "ResolverQueryLogConfig"
        ],
        lambda c: c["Status"] == "CREATED",
        timeout_s=120,
        interval_s=5,
        description="control query log config reaches CREATED",
    )
    assert settled["OwnerId"] == account, settled
    assert settled["DestinationArn"] == stored_arn, settled

    # A well-formed ARN for a log group that was never created; only its existence differs.
    absent_lg = ctx.unique_name("sim2real-behav-r53r-absent-lg-")
    bad_arn = _log_group_arn(ctx, account, absent_lg)
    bad_name = ctx.unique_name("sim2real-behav-qlc-bad-")

    def bad_destination():
        resp = r53.create_resolver_query_log_config(
            Name=bad_name,
            DestinationArn=bad_arn,
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        )
        ctx.on_cleanup(
            lambda x=resp["ResolverQueryLogConfig"]["Id"]: _delete_when_possible(
                r53.delete_resolver_query_log_config, ResolverQueryLogConfigId=x
            )
        )
        return resp

    refusal = _error(bad_destination)
    # The bracketed [RSLVR-01600] code ties this refusal to the destination check rather
    # than to the caller's own IAM.
    assert refusal == ("AccessDeniedException", "[RSLVR-01600] Access denied"), (
        "expected AccessDeniedException '[RSLVR-01600] Access denied' (as captured in "
        "wire/route53resolver/query-log-config-missing-resource-errors.json step 3) for a "
        f"query log config naming a nonexistent log group, got {refusal!r}"
    )

    # No config with that name exists, in any status.
    listed = _configs_named(r53, bad_name)
    assert listed["ResolverQueryLogConfigs"] == [], (
        f"a refused query log config must not exist in any status, got "
        f"{listed['ResolverQueryLogConfigs']!r}"
    )
    assert listed.get("TotalFilteredCount") == 0, (
        f"the filtered count must agree with the empty list, got {listed!r}"
    )

    # CONTROL STILL WORKS: the good config is untouched and still findable by name.
    good_listed = _configs_named(r53, good_name)["ResolverQueryLogConfigs"]
    assert [c["Id"] for c in good_listed] == [config_id], (
        f"the control config must still be the only match for {good_name!r}, got "
        f"{[c.get('Id') for c in good_listed]}"
    )
    assert good_listed[0]["Status"] == "CREATED", good_listed[0]
    assert good_listed[0]["DestinationArn"] == stored_arn, good_listed[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
