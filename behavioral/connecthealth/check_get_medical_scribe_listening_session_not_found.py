"""get-medical-scribe-listening-session-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-medical-scribe-listening-session-not-found"
GROUP = "error-semantics"
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
    """GetMedicalScribeListeningSession on a well-formed but never-started sessionId returns ResourceNotFoundException,
    scoped to the real domain/subscription that legitimately exist."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real": CHECK})["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id))

    # positive control: the domain/subscription pair backing the lookup is real and ACTIVE
    pre_status = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]["status"]
    assert pre_status == "ACTIVE", f"expected positive-control subscription status ACTIVE, got {pre_status!r}"

    never_started_session_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: ch.get_medical_scribe_listening_session(
            sessionId=never_started_session_id, domainId=domain_id, subscriptionId=subscription_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected GetMedicalScribeListeningSession on a never-started sessionId to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = f"Resource not found: sessionId with ID {never_started_session_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect isolation: the real subscription is unaffected by the failed session lookup
    post_status = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]["status"]
    assert post_status == "ACTIVE", f"expected subscription status ACTIVE after the failed lookup, got {post_status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

