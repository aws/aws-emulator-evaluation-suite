"""health-check-inventory-and-status."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "health-check-inventory-and-status"
GROUP = 'health-check'
SERVICES = ['route53']

#: Fresh resources tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _health_check_fqdn(ctx):
    """A name under the reserved .invalid TLD: it never resolves, so the health check probes no host."""
    return f"{ctx.unique_name('sim2real-behav-hc').lower()}.invalid"


def _create_health_check(ctx, r53, port=80):
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "FullyQualifiedDomainName": _health_check_fqdn(ctx),
            "Port": port,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: r53.delete_health_check(HealthCheckId=i))
    return hc_id


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _settled_count(probe, expected, *, timeout_s=30.0, interval_s=2.0):
    """probe() once it equals ``expected``, else the last value read at the deadline; the count
    is eventually consistent."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if last == expected or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new health check is listed, counted, and exposes not-found semantics via GetHealthCheckStatus."""
    r53 = ctx.client("route53")
    # GetHealthCheckCount is account-wide, so a health check another run creates or deletes
    # meanwhile moves it too: each attempt makes a fresh health check, and only a window in which
    # the count moved by exactly our own one is graded.
    for _ in range(_ATTEMPTS):
        before = r53.get_health_check_count()["HealthCheckCount"]
        hc_id = _create_health_check(ctx, r53)
        after = _settled_count(
            lambda: r53.get_health_check_count()["HealthCheckCount"], before + 1
        )
        if after == before + 1:
            break

    found = False
    kwargs: dict = {}
    while True:
        page = r53.list_health_checks(**kwargs)
        if any(c["Id"] == hc_id for c in page["HealthChecks"]):
            found = True
            break
        if not page.get("IsTruncated"):
            break
        kwargs = {"Marker": page["NextMarker"]}
    assert found, f"{hc_id} missing from ListHealthChecks"

    assert after == before + 1, (
        f"GetHealthCheckCount should increase by exactly 1, got {before} -> {after} in the last "
        f"of {_ATTEMPTS} attempts"
    )

    # GetHealthCheckStatus / GetHealthCheckLastFailureReason are served from the
    # distributed checker fleet, which registers a newly created health check
    # asynchronously — right after CreateHealthCheck they still answer
    # NoSuchHealthCheck for an id that GetHealthCheck resolves fine. That race
    # makes the fresh-check status non-deterministic, so the deterministic
    # contract pinned here is the not-found semantics for an id that never
    # existed, plus the fact that the check itself IS immediately readable.
    got_id = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]["Id"]
    assert got_id == hc_id, f"GetHealthCheck returned {got_id}, expected {hc_id}"

    unknown = str(uuid.uuid4())
    status_err = _client_error(lambda: r53.get_health_check_status(HealthCheckId=unknown))
    assert status_err["Code"] == "NoSuchHealthCheck", f"expected NoSuchHealthCheck from status, got {status_err}"
    assert status_err["Message"] == f"A health check with id {unknown} does not exist.", status_err

    failure_err = _client_error(
        lambda: r53.get_health_check_last_failure_reason(HealthCheckId=unknown)
    )
    assert failure_err["Code"] == "NoSuchHealthCheck", (
        f"expected NoSuchHealthCheck from last-failure-reason, got {failure_err}"
    )
    assert failure_err["Message"] == f"A health check with id {unknown} does not exist.", failure_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
