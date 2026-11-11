"""authorization-token-duration-below-minimum-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorization-token-duration-below-minimum-rejected"
GROUP = 'authorization-tokens-rejected'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the call SUCCEEDED where real AWS rejects it — there is no error code to compare"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken with durationSeconds=100 (below 900) and 999999 (above the maximum)
    each fail with ValidationException and their exact messages, while durationSeconds=900, the
    smallest legal non-zero duration, mints a token lasting about 900 s."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    code, message = _error(lambda: ca.get_authorization_token(domain=domain, durationSeconds=100))
    assert code == "ValidationException", (
        f"durationSeconds=100 returned {code!r}, expected ValidationException"
    )
    expected = ("Invalid durationSeconds value of 100: value must be 0 or between 900 and 43200 "
                "(inclusive).")
    assert message == expected, (
        f"the message for durationSeconds=100 was {message!r}, expected {expected!r}: the "
        f"service's own discontinuous rule, which is what a model-range-only emulator will not have"
    )

    code, message = _error(lambda: ca.get_authorization_token(domain=domain,
                                                             durationSeconds=999999))
    assert code == "ValidationException", (
        f"durationSeconds=999999 returned {code!r}, expected ValidationException"
    )
    expected = ("1 validation error detected: Value '999999' at 'durationSeconds' failed to satisfy "
                "constraint: Member must have value less than or equal to 43200")
    assert message == expected, (
        f"the message for durationSeconds=999999 was {message!r}, expected {expected!r}: the "
        f"modelled-range refusal, a different layer from the low-end one above"
    )

    before = datetime.datetime.now(datetime.timezone.utc)
    ok = ca.get_authorization_token(domain=domain, durationSeconds=900)
    lifetime = (ok["expiration"] - before).total_seconds()
    # Two-sided: the service stamps the expiry when it processes the call, so the lifetime read
    # from the pre-call instant lands just under the requested duration (measured 899.1s).
    assert 870 <= lifetime <= 960, (
        f"the positive control (durationSeconds=900, the smallest legal non-zero duration) "
        f"produced an expiry {lifetime:.1f}s away, expected about 900s"
    )
    assert len(ok["authorizationToken"]) > 100, (
        f"the control token is {len(ok['authorizationToken'])} characters long, which is not a "
        f"CodeArtifact bearer token"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
