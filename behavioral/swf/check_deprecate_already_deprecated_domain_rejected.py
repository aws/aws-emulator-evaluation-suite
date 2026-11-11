"""deprecate-already-deprecated-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deprecate-already-deprecated-domain-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeprecateDomain called twice on the same domain returns DomainDeprecatedFault on the second
    call; undeprecating the domain then reverses the block and the identical DeprecateDomain call
    succeeds again."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-domain-")
    swf.register_domain(
        name=domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "sim2real", "value": "audit"}],
    )
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, domain))

    # Positive control: the first DeprecateDomain call on a freshly-registered domain succeeds.
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    swf.deprecate_domain(name=domain)
    info = swf.describe_domain(name=domain)
    assert info["domainInfo"]["status"] == "DEPRECATED", (
        f"the first DeprecateDomain call must succeed; DescribeDomain reported "
        f"{info['domainInfo']['status']!r}"
    )

    # Break: a second DeprecateDomain on the now-DEPRECATED domain is rejected.
    code, message = _error(lambda: swf.deprecate_domain(name=domain))
    assert code == "DomainDeprecatedFault", (
        f"a second DeprecateDomain on an already-deprecated domain must fail with "
        f"DomainDeprecatedFault; got {code!r}"
    )
    assert message == domain, f"expected the fault message to be the domain name {domain!r}, got {message!r}"

    # Effect absent: the rejected second deprecation left the domain's status unchanged.
    info_after = swf.describe_domain(name=domain)
    assert info_after["domainInfo"]["status"] == "DEPRECATED", (
        f"the rejected second DeprecateDomain must not change status; DescribeDomain reported "
        f"{info_after['domainInfo']['status']!r}"
    )

    # Restore: UndeprecateDomain reverses the block on this same domain.
    _undeprecate_with_retry(swf, domain)
    restored = swf.describe_domain(name=domain)
    assert restored["domainInfo"]["status"] == "REGISTERED", (
        f"UndeprecateDomain must return the domain to REGISTERED; got "
        f"{restored['domainInfo']['status']!r}"
    )

    # The identical call that was rejected above now succeeds against the same domain.
    swf.deprecate_domain(name=domain)
    final = swf.describe_domain(name=domain)
    assert final["domainInfo"]["status"] == "DEPRECATED", (
        f"the identical DeprecateDomain call must succeed once the domain is restored to "
        f"REGISTERED; got {final['domainInfo']['status']!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_deprecate(swf, name):
    try:
        swf.deprecate_domain(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DomainDeprecatedFault", "UnknownResourceFault"):
            raise


def _undeprecate_with_retry(swf, name, timeout=60, interval=3):
    """UndeprecateDomain's own internal read of domain status can lag behind what DescribeDomain
    already reports (a separate consistency boundary), so a DomainAlreadyExistsFault right after
    the domain settles into DEPRECATED is a transient race, not a real rejection -- retry it
    bounded."""
    import time

    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            swf.undeprecate_domain(name=name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DomainAlreadyExistsFault":
                raise
            last_err = err
            time.sleep(interval)
    raise AssertionError(f"UndeprecateDomain on deprecated domain {name} never settled: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
