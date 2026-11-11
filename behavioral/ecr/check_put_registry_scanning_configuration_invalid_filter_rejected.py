"""put-registry-scanning-configuration-invalid-filter-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "put-registry-scanning-configuration-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """PutRegistryScanningConfiguration with a malformed repository filter pattern (uppercase
    letters / invalid characters are not allowed in an ECR repository filter) is rejected with
    InvalidParameterException, and the account's scanning configuration is left unchanged."""
    ecr = ctx.client("ecr")
    original = _get_scanning_config(ecr)

    # Positive control: a well-formed configuration is accepted. Stays on BASIC/
    # SCAN_ON_PUSH to avoid triggering an ENHANCED (Inspector) activation transition,
    # which would leave the account in a transient state that could collide with other
    # checks touching registry scanning configuration.
    good_config = {
        "scanType": "BASIC",
        "rules": [
            {
                "scanFrequency": "SCAN_ON_PUSH",
                "repositoryFilters": [
                    {"filter": ctx.unique_name("sim2real-ecr-ok-") + "*", "filterType": "WILDCARD"}
                ],
            }
        ],
    }
    ctx.on_cleanup(lambda: _restore_scanning_config(ecr, original))
    _put_with_backoff(ecr, good_config)
    settled = _poll_until(
        probe=lambda: _get_scanning_config(ecr),
        predicate=lambda c: c is not None and c.get("scanType") == "BASIC",
        timeout_s=60,
        interval_s=5,
        description="positive-control scanning configuration settling to BASIC",
    )
    assert settled is not None and settled["scanType"] == "BASIC", (
        f"positive-control scanning configuration did not settle to BASIC: {settled!r}"
    )

    # Negative: an invalid filter pattern (uppercase + invalid symbols) is rejected.
    bad_filter = "INVALID FILTER!!"
    code, message = _client_error(
        lambda: ecr.put_registry_scanning_configuration(
            scanType="BASIC",
            rules=[
                {
                    "scanFrequency": "SCAN_ON_PUSH",
                    "repositoryFilters": [{"filter": bad_filter, "filterType": "WILDCARD"}],
                }
            ],
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for malformed filter {bad_filter!r}, got {code!r}"
    )
    expected_message = (
        "Invalid parameter at 'rules.1.member.repositoryFilters.1.member.filter' failed to "
        "satisfy constraint: 'Member must satisfy regular expression pattern: "
        "^(?:[a-z0-9*]+(?:[._-][a-z0-9*]+)*/)*[a-z0-9*]+(?:[._-][a-z0-9*]+)*$'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the good configuration from the positive control is still in place,
    # the rejected call did not partially apply. Poll briefly: GetRegistryScanningConfiguration
    # can lag by a beat right after a write.
    current = _poll_until(
        probe=lambda: _get_scanning_config(ecr),
        predicate=lambda c: c is not None,
        timeout_s=30,
        interval_s=3,
        description="scanning configuration reappearing after a rejected write",
    )
    assert current is not None, "scanning configuration disappeared after a rejected write"
    assert current["scanType"] == "BASIC", f"scanType changed after rejected write: {current!r}"
    expected_filter = good_config["rules"][0]["repositoryFilters"][0]["filter"]
    actual_filter = current["rules"][0]["repositoryFilters"][0]["filter"]
    assert actual_filter == expected_filter, (
        f"repository filter changed after rejected write: expected {expected_filter!r}, "
        f"got {actual_filter!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and _time.monotonic() < deadline:
        _time.sleep(min(interval_s, max(0.0, deadline - _time.monotonic())))
        value = probe()
    if not predicate(value):
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")
    return value


def _client_error(fn) -> tuple[str, str | None]:
    """Calls fn(); returns the ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected PutRegistryScanningConfiguration to be rejected, but it succeeded and returned {result!r}"
    )


def _put_with_backoff(ecr, kwargs: dict[str, Any], *, timeout_s: float = 90, interval_s: float = 5) -> None:
    """Calls PutRegistryScanningConfiguration; retries a transient account-state conflict
    (an ENABLE_IN_PROGRESS/DISABLE_IN_PROGRESS Inspector activation transition left over
    from another check touching this same account-level singleton config) instead of
    treating it as the final outcome. Any other error propagates."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            ecr.put_registry_scanning_configuration(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if (
                code == "InvalidParameterException"
                and "IN_PROGRESS" in message
                and _time.monotonic() < deadline
            ):
                _time.sleep(interval_s)
                continue
            raise


def _get_scanning_config(ecr) -> dict[str, Any] | None:
    resp = ecr.get_registry_scanning_configuration()
    return resp.get("scanningConfiguration")


def _restore_scanning_config(ecr, original: dict[str, Any] | None) -> None:
    kwargs = (
        {"scanType": "BASIC", "rules": []}
        if original is None
        else {"scanType": original.get("scanType", "BASIC"), "rules": original.get("rules", [])}
    )
    _put_with_backoff(ecr, kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
