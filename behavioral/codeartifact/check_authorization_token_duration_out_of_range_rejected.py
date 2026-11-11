"""authorization-token-duration-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "authorization-token-duration-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken with durationSeconds=43201 (one past the maximum) and 500 (between 0
    and 900) each fail with ValidationException and their exact messages instead of being clamped,
    while a valid duration mints a token with an expiration."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    # One past the documented maximum of 43200.
    code_above_max, msg_above_max = _error(
        lambda: ca.get_authorization_token(domain=domain, durationSeconds=43201))
    assert code_above_max == "ValidationException", (
        f"durationSeconds=43201 returned {code_above_max!r}, expected ValidationException"
    )
    expected_above_max = ("1 validation error detected: Value '43201' at 'durationSeconds' failed "
                          "to satisfy constraint: Member must have value less than or equal to 43200")
    assert msg_above_max == expected_above_max, (
        f"the message for durationSeconds=43201 was {msg_above_max!r}, expected "
        f"{expected_above_max!r}"
    )

    # Inside the disallowed gap (1-899): only 0 or [900, 43200] are valid.
    code_in_gap, msg_in_gap = _error(
        lambda: ca.get_authorization_token(domain=domain, durationSeconds=500))
    assert code_in_gap == "ValidationException", (
        f"durationSeconds=500 returned {code_in_gap!r}, expected ValidationException"
    )
    expected_in_gap = ("Invalid durationSeconds value of 500: value must be 0 or between 900 and "
                       "43200 (inclusive).")
    assert msg_in_gap == expected_in_gap, (
        f"the message for durationSeconds=500 was {msg_in_gap!r}, expected {expected_in_gap!r}"
    )

    # Positive control: a value within the documented bound still succeeds, and
    # neither out-of-range call above silently clamped and returned a usable token.
    resp = ca.get_authorization_token(domain=domain, durationSeconds=900)
    assert "authorizationToken" in resp and len(resp["authorizationToken"]) > 100, (
        f"the positive control's authorizationToken was {resp.get('authorizationToken')!r}, "
        f"expected a real CodeArtifact bearer token"
    )
    assert "expiration" in resp, (
        f"the positive control response {resp!r} carried no expiration"
    )


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this durationSeconds, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
