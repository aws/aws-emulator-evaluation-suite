"""undeprecate-active-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "undeprecate-active-domain-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UndeprecateDomain on a currently-REGISTERED (not deprecated) domain returns DomainAlreadyExistsFault."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-domain-")
    swf.register_domain(name=domain, workflowExecutionRetentionPeriodInDays="1")
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, domain))

    code, message = _error(lambda: swf.undeprecate_domain(name=domain))
    assert code == "DomainAlreadyExistsFault", (
        f"expected DomainAlreadyExistsFault undeprecating a REGISTERED domain, got {code!r}"
    )
    assert message == domain, f"expected message {domain!r}, got {message!r}"

    # Effect absent: status remains REGISTERED, unaffected by the rejected call.
    info = swf.describe_domain(name=domain)
    status = info["domainInfo"]["status"]
    assert status == "REGISTERED", f"expected domain {domain} to remain REGISTERED, got {status!r}"

    # Positive control: deprecate-then-undeprecate a fresh domain transitions it back to REGISTERED.
    # DeprecateDomain's status change can lag briefly, so poll DescribeDomain until it reports
    # DEPRECATED before calling UndeprecateDomain (otherwise UndeprecateDomain itself can observe
    # the still-REGISTERED state and reject with DomainAlreadyExistsFault).
    control_domain = ctx.unique_name("sim2real-behav-domain-ctl-")
    swf.register_domain(name=control_domain, workflowExecutionRetentionPeriodInDays="1")
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, control_domain))
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    swf.deprecate_domain(name=control_domain)
    _wait_for_status(swf, control_domain, "DEPRECATED")
    _undeprecate_with_retry(swf, control_domain)
    control_info = swf.describe_domain(name=control_domain)
    control_status = control_info["domainInfo"]["status"]
    assert control_status == "REGISTERED", (
        f"expected undeprecated domain {control_domain} to read back REGISTERED, got {control_status!r}"
    )


def _error(fn):
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


def _wait_for_status(swf, name, want, timeout=60, interval=2):
    import time

    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = swf.describe_domain(name=name)["domainInfo"]["status"]
        if last == want:
            return
        time.sleep(interval)
    raise AssertionError(f"domain {name} status {last!r} never reached {want!r} within {timeout}s")


def _undeprecate_with_retry(swf, name, timeout=60, interval=3):
    """UndeprecateDomain's own internal read of domain status can lag behind what DescribeDomain
    already reports (a separate consistency boundary), so a DomainAlreadyExistsFault right after the
    domain settles into DEPRECATED is a transient race, not a real rejection -- retry it bounded."""
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
