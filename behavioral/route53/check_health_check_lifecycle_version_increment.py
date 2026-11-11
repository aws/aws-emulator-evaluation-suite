"""health-check-lifecycle-version-increment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-lifecycle-version-increment"
GROUP = 'health-check'
SERVICES = ['route53']

# Health checks target names under the reserved .invalid TLD, which never resolve, so the
# health checker sends no traffic to any host.
_HC_SUFFIX = ".invalid"

# Transient/server-side conditions that are safe to retry. Route 53's control plane
# occasionally sheds control-plane creates, which would show up as a bogus failure.
_TRANSIENT_CODES = frozenset(
    {
        "ServiceUnavailable",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "PriorRequestNotComplete",
        "InternalServiceError",
        "InternalFailure",
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHealthCheck increments HealthCheckVersion by exactly 1; reusing a CallerReference
    with a different config on create is rejected."""
    r53 = ctx.client("route53")
    hc_id = _new_health_check(ctx, r53)
    created = r53.get_health_check(HealthCheckId=hc_id)
    v0 = created["HealthCheck"]["HealthCheckVersion"]

    updated = r53.update_health_check(
        HealthCheckId=hc_id, HealthCheckVersion=v0, ResourcePath="/healthz"
    )
    assert updated["HealthCheck"]["HealthCheckVersion"] == v0 + 1, (
        f"expected version {v0 + 1}, got {updated['HealthCheck']['HealthCheckVersion']}"
    )
    assert updated["HealthCheck"]["HealthCheckConfig"]["ResourcePath"] == "/healthz", (
        updated["HealthCheck"]["HealthCheckConfig"]
    )

    fetched = r53.get_health_check(HealthCheckId=hc_id)
    assert fetched["HealthCheck"]["HealthCheckVersion"] == v0 + 1, (
        f"expected version {v0 + 1} on independent read, got "
        f"{fetched['HealthCheck']['HealthCheckVersion']}"
    )
    assert fetched["HealthCheck"]["HealthCheckConfig"]["ResourcePath"] == "/healthz", (
        fetched["HealthCheck"]["HealthCheckConfig"]
    )

    # a distinct create-time boundary: reusing a CallerReference with a
    # different HealthCheckConfig must be rejected, not silently accepted
    # or treated as idempotent; reusing it with the IDENTICAL config must
    # replay idempotently rather than erroring or forking a second resource.
    dup_ref = _caller_reference(ctx, "hc-dup")
    dup_fqdn = ctx.unique_name("sim2real-behav-hc-dup-") + _HC_SUFFIX
    original_config = {
        "FullyQualifiedDomainName": dup_fqdn,
        "Port": 80,
        "Type": "HTTP",
        "RequestInterval": 30,
        "FailureThreshold": 3,
    }
    dup_created = r53.create_health_check(
        CallerReference=dup_ref,
        HealthCheckConfig=original_config,
    )
    dup_id = dup_created["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: _delete_health_check(r53, dup_id))
    dup_v0 = dup_created["HealthCheck"]["HealthCheckVersion"]

    dup_err = _client_error(
        lambda: r53.create_health_check(
            CallerReference=dup_ref,
            HealthCheckConfig={
                # different config, same CallerReference
                "FullyQualifiedDomainName": dup_fqdn,
                "Port": 443,
                "Type": "HTTPS",
                "RequestInterval": 30,
                "FailureThreshold": 3,
            },
        ),
        # if the target wrongly accepts this, it minted a second resource we must still clean up
        on_unexpected_success=lambda resp: ctx.on_cleanup(
            lambda: _delete_health_check(r53, resp["HealthCheck"]["Id"])
        ),
    )
    assert dup_err["Code"] == "HealthCheckAlreadyExists", (
        f"expected HealthCheckAlreadyExists, got {dup_err}"
    )
    assert dup_err["Message"] == (
        "A different health check has already been created with the specified caller reference. "
        "If that health check has been deleted, Route 53 will still maintain the caller reference "
        "for a number of days."
    ), dup_err

    # effect-absent: the rejected attempt must not have touched the existing resource
    unchanged = r53.get_health_check(HealthCheckId=dup_id)
    assert unchanged["HealthCheck"]["HealthCheckConfig"]["Port"] == 80, (
        "rejected duplicate create mutated the existing health check's config: "
        f"{unchanged['HealthCheck']['HealthCheckConfig']}"
    )
    assert unchanged["HealthCheck"]["HealthCheckVersion"] == dup_v0, (
        f"expected version to stay at {dup_v0} after a rejected create, got "
        f"{unchanged['HealthCheck']['HealthCheckVersion']}"
    )

    # restore: the identical call (same ref, same config) now succeeds — as an
    # idempotent replay of the existing resource, not a fresh create
    replay = r53.create_health_check(
        CallerReference=dup_ref,
        HealthCheckConfig=original_config,
    )
    assert replay["HealthCheck"]["Id"] == dup_id, (
        f"expected idempotent replay to return {dup_id}, got {replay['HealthCheck']['Id']}"
    )

    # terminal independent read: the idempotent replay must not have changed anything either
    final = r53.get_health_check(HealthCheckId=dup_id)
    assert final["HealthCheck"]["HealthCheckConfig"]["Port"] == 80, (
        f"idempotent replay changed the existing health check's config: "
        f"{final['HealthCheck']['HealthCheckConfig']}"
    )
    assert final["HealthCheck"]["HealthCheckVersion"] == dup_v0, (
        f"expected version to stay at {dup_v0} after an idempotent replay, got "
        f"{final['HealthCheck']['HealthCheckVersion']}"
    )


def _client_error(fn, on_unexpected_success=None):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _caller_reference(ctx, prefix="r53") -> str:
    return ctx.unique_name(f"sim2real-behav-{prefix}-")


def _retry_transient(fn, timeout_s=120, interval_s=2.0):
    """Retry fn() while it raises a retryable Route 53 condition."""

    def probe():
        try:
            return ("ok", fn())
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in _TRANSIENT_CODES:
                return ("retry", None)
            raise

    _status, result = _poll_until(
        probe,
        lambda r: r[0] == "ok",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="operation to stop returning a transient Route 53 error",
    )
    return result


def _delete_health_check(r53, hc_id):
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
            raise


def _new_health_check(ctx, r53, port: int = 80) -> str:
    """Create an HTTP health check targeting a non-resolving synthetic FQDN.

    Real AWS rejects RFC-5737 documentation IPs outright ("IPv4 address 192.0.2.200 is
    forbidden"), and pointing a health checker at an arbitrary routable IP would send real
    traffic to a third party. A FullyQualifiedDomainName that resolves for nobody satisfies
    validation and generates no external traffic. This check never asserts on health STATUS,
    only on the resource's own state machine.
    """
    resp = _retry_transient(
        lambda: r53.create_health_check(
            CallerReference=_caller_reference(ctx, "hc"),
            HealthCheckConfig={
                "FullyQualifiedDomainName": ctx.unique_name("sim2real-behav-hc-")
                + _HC_SUFFIX,
                "Port": port,
                "Type": "HTTP",
                "ResourcePath": "/",
                "RequestInterval": 30,
                "FailureThreshold": 3,
            },
        )
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: _delete_health_check(r53, hc_id))
    return hc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
