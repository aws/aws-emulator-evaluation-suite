"""create-domain-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-domain-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_code(fn, expected_code, *, deadline_s=30.0, interval_s=1.0):
    """Retry fn() until it reports expected_code; return that error's message.

    DeleteDomain is synchronous, but the follow-on read can lag the boundary by a beat, so this
    bounds the wait instead of asserting exactly at the transition.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
            last_code = None
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == expected_code:
                return err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected_code} within {deadline_s}s, last saw {last_code}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain with an already-existing name is rejected with ConflictException, not a no-op;
    deleting the original frees the name so the identical call then succeeds."""
    ca = ctx.client("codeartifact")
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()

    first = ca.create_domain(domain=domain)["domain"]
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    refusal = _error(lambda: ca.create_domain(domain=domain))
    expected = ("ConflictException", f"Domain '{domain}' owned by '{ctx.account}' already exists.")
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Effect absent: the original domain is untouched (same ARN, still describable).
    described = ca.describe_domain(domain=domain)["domain"]
    assert described["arn"] == first["arn"], f"expected arn {first['arn']!r}, got {described['arn']!r}"
    assert described["status"] == "Active", f"expected status Active, got {described['status']!r}"

    # Restore: delete the original, confirm it is gone, then the identical call succeeds.
    ca.delete_domain(domain=domain)
    gone = _poll_until_code(lambda: ca.describe_domain(domain=domain), "ResourceNotFoundException")
    expected_gone = (
        f"Domain not found. Domain '{domain}' owned by account '{ctx.account}' does not exist."
    )
    assert gone == expected_gone, f"expected {expected_gone!r}, got {gone!r}"

    restored = ca.create_domain(domain=domain)["domain"]
    assert restored["name"] == domain, f"expected name {domain!r}, got {restored['name']!r}"
    assert restored["status"] == "Active", f"expected status Active, got {restored['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
