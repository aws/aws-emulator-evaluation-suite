"""get-idle-recommendations-max-results-over-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-idle-recommendations-max-results-over-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetIdleRecommendations documents maxResults as ranging 0-100; a value above that
    quota is rejected with InvalidParameterValueException, while the same call with a
    maxResults value inside the documented range succeeds.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)

    code, message = _error(lambda: co.get_idle_recommendations(maxResults=101))
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for maxResults=101, got {code!r}"
    )
    expected = "Invalid Max Results."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: an in-range maxResults on the same operation succeeds
    resp = co.get_idle_recommendations(maxResults=100)
    assert isinstance(resp["idleRecommendations"], list), (
        f"expected idleRecommendations to be a list, got {resp.get('idleRecommendations')!r}"
    )


def _error(fn):
    """Returns the server-returned error (Code, Message) for a ClientError; raises on an unexpected
    SUCCESS rather than returning a falsy sentinel, because an over-permissive target accepting the
    call is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
