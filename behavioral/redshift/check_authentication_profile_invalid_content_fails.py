"""authentication-profile-invalid-content-fails."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling, which is not a behavioral observation."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "authentication-profile-invalid-content-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthenticationProfile rejects non-JSON content and stores nothing; a valid-JSON
    control on the same operation succeeds, so the rejection is due to the malformed content."""
    rs = ctx.client("redshift")
    control_name = ctx.unique_name("sim2real-behav-rs-authpok-")
    ctx.on_cleanup(lambda: rs.delete_authentication_profile(AuthenticationProfileName=control_name))
    control = rs.create_authentication_profile(
        AuthenticationProfileName=control_name,
        AuthenticationProfileContent=json.dumps({"AllowDBUserOverride": "1", "Client_ID": "sim2real-behav"}),
    )
    assert control["AuthenticationProfileName"] == control_name, (
        f"positive control must succeed with valid JSON content, got {control}"
    )

    profile_name = ctx.unique_name("sim2real-behav-rs-authpbad-")
    codes = {
        "create-non-json": _err(lambda: rs.create_authentication_profile(
            AuthenticationProfileName=profile_name,
            AuthenticationProfileContent="not-json-at-all",
        )),
        "describe-after-reject": _err(lambda: rs.describe_authentication_profiles(
            AuthenticationProfileName=profile_name
        )),
    }
    expected = {
        "create-non-json": "InvalidAuthenticationProfileRequestFault",
        "describe-after-reject": "AuthenticationProfileNotFoundFault",
    }
    assert codes == expected, (
        f"invalid authentication-profile content must be rejected and not stored:\n"
        f" expected={expected}\n observed={codes}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
