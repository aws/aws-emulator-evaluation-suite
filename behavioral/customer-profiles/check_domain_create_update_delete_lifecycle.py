"""domain-create-update-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-create-update-delete-lifecycle"
GROUP = "state"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain -> GetDomain -> UpdateDomain -> GetDomain reflects change -> DeleteDomain -> GetDomain 404s."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    got = cp.get_domain(DomainName=domain)
    assert got["DomainName"] == domain, f"expected DomainName {domain!r}, got {got['DomainName']!r}"
    assert got["DefaultExpirationDays"] == 30, (
        f"expected DefaultExpirationDays 30, got {got['DefaultExpirationDays']!r}"
    )

    cp.update_domain(DomainName=domain, DefaultExpirationDays=60)
    updated = _poll_until(
        lambda: cp.get_domain(DomainName=domain),
        lambda r: r["DefaultExpirationDays"] == 60,
        timeout_s=30,
    )
    assert updated["DefaultExpirationDays"] == 60, (
        f"expected DefaultExpirationDays 60 after update, got {updated['DefaultExpirationDays']!r}"
    )

    cp.delete_domain(DomainName=domain)
    code, message = _error(lambda: cp.get_domain(DomainName=domain))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Domain {domain} is not found", (
        f"unexpected GetDomain message for deleted domain {domain!r}: {message!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: cp.update_domain(DomainName=domain, DefaultExpirationDays=90)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected update on deleted domain to fail with ResourceNotFoundException, got {mutate_code!r}"
    )
    # AWS answers UpdateDomain on a deleted domain with no message at all.
    assert mutate_message is None, (
        f"expected UpdateDomain on deleted domain to carry no message, got {mutate_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
