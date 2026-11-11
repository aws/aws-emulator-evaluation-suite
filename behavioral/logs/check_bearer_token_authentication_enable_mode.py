"""bearer-token-authentication-enable-mode."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "bearer-token-authentication-enable-mode"
GROUP = "state-machine"
SERVICES = ["logs"]


def _describe(logs, name: str) -> dict:
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == name]
    assert len(matches) == 1, f"expected exactly one log group named {name!r}, found {len(matches)}"
    return matches[0]


def _poll_until_bearer_enabled(logs, name: str, expected: bool, *, timeout_s: float = 30.0, interval_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    actual = bool(_describe(logs, name)["bearerTokenAuthenticationEnabled"])
    while actual is not expected:
        if time.monotonic() >= deadline:
            return actual
        time.sleep(interval_s)
        actual = bool(_describe(logs, name)["bearerTokenAuthenticationEnabled"])
    return actual


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication toggles bearerTokenAuthenticationEnabled, observable via DescribeLogGroups."""
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-bearer-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))

    # Newly created log groups default to bearer-token auth disabled.
    initial = bool(_describe(logs, name)["bearerTokenAuthenticationEnabled"])
    assert initial is False, f"expected a freshly created log group to have bearer auth disabled, got {initial}"

    resp_enable = logs.put_bearer_token_authentication(
        logGroupIdentifier=name, bearerTokenAuthenticationEnabled=True
    )
    status_enable = resp_enable["ResponseMetadata"]["HTTPStatusCode"]
    assert status_enable == 200, f"expected HTTP 200 enabling bearer auth, got {status_enable}"
    enabled = _poll_until_bearer_enabled(logs, name, True)
    assert enabled is True, f"expected bearerTokenAuthenticationEnabled=True after enabling, got {enabled}"

    resp_disable = logs.put_bearer_token_authentication(
        logGroupIdentifier=name, bearerTokenAuthenticationEnabled=False
    )
    status_disable = resp_disable["ResponseMetadata"]["HTTPStatusCode"]
    assert status_disable == 200, f"expected HTTP 200 disabling bearer auth, got {status_disable}"
    disabled = _poll_until_bearer_enabled(logs, name, False)
    assert disabled is False, f"expected bearerTokenAuthenticationEnabled=False after disabling, got {disabled}"

    # Re-enabling by ARN (instead of bare name) mutates the same underlying resource.
    arn = _describe(logs, name)["logGroupArn"]
    logs.put_bearer_token_authentication(
        logGroupIdentifier=arn, bearerTokenAuthenticationEnabled=True
    )
    reenabled = _poll_until_bearer_enabled(logs, name, True)
    assert reenabled is True, f"expected bearerTokenAuthenticationEnabled=True after ARN-identified enable, got {reenabled}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
