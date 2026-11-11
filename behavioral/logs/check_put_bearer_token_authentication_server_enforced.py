"""put-bearer-token-authentication-server-enforced."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-bearer-token-authentication-server-enforced"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication persists an authentication mode server-side:
    the flag is durably stored and independently observable via DescribeLogGroups,
    not merely echoed back by the write call itself."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-bearer-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    initial = _describe(logs, group)
    assert initial.get("bearerTokenAuthenticationEnabled", False) is False, (
        f"expected a freshly created log group to default to bearer-token auth disabled, "
        f"got {initial.get('bearerTokenAuthenticationEnabled')!r}"
    )

    logs.put_bearer_token_authentication(logGroupIdentifier=group, bearerTokenAuthenticationEnabled=True)
    enabled = _poll_until(
        lambda: _describe(logs, group),
        lambda lg: lg.get("bearerTokenAuthenticationEnabled") is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert enabled["bearerTokenAuthenticationEnabled"] is True, (
        f"expected DescribeLogGroups to independently report bearer-token auth enabled "
        f"after PutBearerTokenAuthentication(True), got {enabled.get('bearerTokenAuthenticationEnabled')!r}"
    )

    logs.put_bearer_token_authentication(logGroupIdentifier=group, bearerTokenAuthenticationEnabled=False)
    disabled = _poll_until(
        lambda: _describe(logs, group),
        lambda lg: lg.get("bearerTokenAuthenticationEnabled", False) is False,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert disabled.get("bearerTokenAuthenticationEnabled", False) is False, (
        f"expected DescribeLogGroups to independently report bearer-token auth disabled "
        f"after PutBearerTokenAuthentication(False), got {disabled.get('bearerTokenAuthenticationEnabled')!r}"
    )


def _describe(logs, group: str) -> dict:
    matches = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
    assert matches, f"log group {group!r} disappeared"
    return matches[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
