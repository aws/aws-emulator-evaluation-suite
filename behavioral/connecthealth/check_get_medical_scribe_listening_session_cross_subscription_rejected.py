"""get-medical-scribe-listening-session-cross-subscription-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-medical-scribe-listening-session-cross-subscription-rejected"
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
    """GetMedicalScribeListeningSession rejects a sessionId lookup scoped to a Subscription that is not the one
    the (never-started) session was addressed to — the API must not leak existence across subscriptions/domains."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_a = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_a))
    subscription_b = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_b))

    session_id = str(uuid.uuid4())

    # positive control: looking the (never-started) session up under its "home" subscription 404s cleanly
    expected = f"Resource not found: sessionId with ID {session_id} does not exist"
    code_home, message_home = _client_error(
        lambda: ch.get_medical_scribe_listening_session(
            sessionId=session_id, domainId=domain_id, subscriptionId=subscription_a
        )
    )
    assert code_home == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_home!r}"
    assert message_home == expected, f"expected message {expected!r}, got {message_home!r}"

    # negative: the same sessionId under an unrelated Subscription in the same Domain must ALSO 404, never leak
    # a different subscription's session (or accept it as valid cross-subscription).
    code_cross, message_cross = _client_error(
        lambda: ch.get_medical_scribe_listening_session(
            sessionId=session_id, domainId=domain_id, subscriptionId=subscription_b
        )
    )
    assert code_cross == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_cross!r}"
    assert message_cross == expected, f"expected message {expected!r}, got {message_cross!r}"

    # effect isolation: both subscriptions remain ACTIVE and independently addressable
    assert ch.get_subscription(domainId=domain_id, subscriptionId=subscription_a)["subscription"]["status"] == "ACTIVE"
    assert ch.get_subscription(domainId=domain_id, subscriptionId=subscription_b)["subscription"]["status"] == "ACTIVE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

