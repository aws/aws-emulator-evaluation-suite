"""resolver-query-log-config-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-query-log-config-lifecycle"
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


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _absent_ok(fn) -> None:
    """Teardown delete that tolerates a resource the check already removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.account


def _create_log_group_arn(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-r53r-behavioral-")
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return f"arn:aws:logs:{ctx.region}:{_account_id(ctx)}:log-group:{name}:*"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResolverQueryLogConfig reaches CREATED, then is gone (ResourceNotFoundException on an
    independent read) after delete, and a second delete on the same id is rejected not-found."""
    r53 = ctx.client("route53resolver")
    dest_arn = _create_log_group_arn(ctx)
    cfg = r53.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-behav-qlc-"),
        DestinationArn=dest_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
    )["ResolverQueryLogConfig"]
    cfg_id = cfg["Id"]
    ctx.on_cleanup(
        lambda x=cfg_id: _absent_ok(lambda: r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=x))
    )
    def cfg_status():
        return r53.get_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)[
            "ResolverQueryLogConfig"
        ]["Status"]

    _poll(cfg_status, lambda s: s == "CREATED", timeout_s=60, interval_s=2)

    r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)

    def cfg_gone():
        try:
            return r53.get_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)[
                "ResolverQueryLogConfig"
            ]["Status"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            return "GONE" if code == "ResourceNotFoundException" else code

    _poll(
        cfg_gone,
        lambda s: s == "GONE",
        timeout_s=60,
        interval_s=3,
        description="query log config gone (ResourceNotFoundException) on independent read after delete",
    )

    delete_again = _error(
        lambda: r53.delete_resolver_query_log_config(ResolverQueryLogConfigId=cfg_id)
    )
    expected = (
        "ResourceNotFoundException",
        "[RSLVR-01601] The specified query logging configuration doesn't exist.",
    )
    assert delete_again == expected, (
        f"expected {expected!r} deleting an already-deleted query log config, got {delete_again!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
