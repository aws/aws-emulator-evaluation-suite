"""delete-access-log-settings-removes-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-access-log-settings-removes-config"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-http"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAccessLogSettings clears a stage's access log destination so a
    subsequent GetStage no longer reports an AccessLogSettings block."""
    apigw = ctx.client("apigatewayv2")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("/sim2real/apigw-access-logs-")
    logs.create_log_group(logGroupName=log_group_name, tags=TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
        "logGroups"
    ][0]["arn"]

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-http-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    stage_name = "sim2real"
    apigw.create_stage(
        ApiId=api_id,
        StageName=stage_name,
        AccessLogSettings={"DestinationArn": log_group_arn, "Format": "$context.requestId"},
    )

    def _arn_matches(s):
        dest = s.get("AccessLogSettings", {}).get("DestinationArn")
        if not dest:
            return False
        # CloudWatch Logs group ARNs may be normalized (trailing ":*" added or
        # stripped) by the service, so compare the un-suffixed form.
        return dest.rstrip("*").rstrip(":") == log_group_arn.rstrip("*").rstrip(":")

    got = _poll_until(
        lambda: apigw.get_stage(ApiId=api_id, StageName=stage_name),
        _arn_matches,
        timeout_s=30,
    )
    assert _arn_matches(got), (
        f"GetStage never reflected the configured AccessLogSettings destination "
        f"(expected arn matching {log_group_arn!r}, "
        f"got {got.get('AccessLogSettings')!r})"
    )

    apigw.delete_access_log_settings(ApiId=api_id, StageName=stage_name)

    got2 = _poll_until(
        lambda: apigw.get_stage(ApiId=api_id, StageName=stage_name),
        lambda s: not s.get("AccessLogSettings"),
        timeout_s=15,
    )
    assert not got2.get("AccessLogSettings"), (
        "GetStage still reports an AccessLogSettings block after "
        "DeleteAccessLogSettings"
    )


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
