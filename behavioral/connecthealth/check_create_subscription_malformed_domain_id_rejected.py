"""create-subscription-malformed-domain-id-rejected."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-subscription-malformed-domain-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["connecthealth"]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so an emulator that
    accepts what AWS refuses reads as a loud failure rather than a code mismatch."""
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
    """CreateSubscription rejects a 21-character domainId with the wrong (hai-|dom-) prefix with
    ValidationException "<id> is not a valid domain id.", and the domain keeps exactly one subscription."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-owner": "behavioral"})["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    # positive control: a well-formed domainId is accepted
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id))
    assert len(ch.list_subscriptions(domainId=domain_id)["subscriptions"]) == 1

    # 21 chars (within the 20-25 length constraint) but the wrong prefix -> reaches the service, fails pattern validation
    bad_domain_id = "xxx-" + "0" * 17
    assert 20 <= len(bad_domain_id) <= 25
    code, message = _client_error(lambda: ch.create_subscription(domainId=bad_domain_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # The message ends with the backend's service name, request id and attempt count, taken from it.
    found = re.search(
        r"\(Service: ([^,]+), Status Code: 400, Request ID: ([0-9a-f-]+)\) \(SDK Attempt Count: (\d+)\)$",
        message or "",
    )
    service, request_id, attempts = found.groups() if found else ("?", "?", "?")
    expected = (
        f"{bad_domain_id} is not a valid domain id. (Service: {service}, Status Code: 400, "
        f"Request ID: {request_id}) (SDK Attempt Count: {attempts})"
    )
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # effect absent: still exactly one subscription under the real domain
    assert len(ch.list_subscriptions(domainId=domain_id)["subscriptions"]) == 1


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
