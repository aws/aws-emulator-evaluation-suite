"""get-domain-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDomain on a well-formed but nonexistent domainId returns ResourceNotFoundException, while a real Domain is unaffected."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    # positive control: the real Domain is gettable
    status = ch.get_domain(domainId=domain_id)["status"]
    assert status == "ACTIVE", f"expected freshly created Domain to be ACTIVE, got {status!r}"

    fake_domain_id = "dom-" + "z" * 21  # matches ^(hai-|dom-)[a-z0-9]+$, 25 chars like a real generated id, never created
    code, message = _client_error(lambda: ch.get_domain(domainId=fake_domain_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Domain not found: {fake_domain_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect isolation: the real Domain is still reachable after the failed lookup
    got_id = ch.get_domain(domainId=domain_id)["domainId"]
    assert got_id == domain_id, f"expected the real Domain {domain_id!r} still reachable, got {got_id!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
