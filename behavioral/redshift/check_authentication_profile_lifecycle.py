"""authentication-profile-lifecycle."""

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
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
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

CHECK = "authentication-profile-lifecycle"
GROUP = 'authentication-profile'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Authentication profiles: content round-trips as JSON, modify replaces it, delete removes it,
    and the name is unique."""
    rs = ctx.client("redshift")
    profile_name = ctx.unique_name("sim2real-behav-rs-authp-")
    ctx.on_cleanup(lambda: rs.delete_authentication_profile(AuthenticationProfileName=profile_name))
    content_v1 = json.dumps({"AllowDBUserOverride": "1", "Client_ID": "sim2real-behav"})
    content_v2 = json.dumps({"AllowDBUserOverride": "0", "Client_ID": "sim2real-behav"})

    created = rs.create_authentication_profile(
        AuthenticationProfileName=profile_name,
        AuthenticationProfileContent=content_v1,
    )
    assert created["AuthenticationProfileName"] == profile_name
    assert json.loads(created["AuthenticationProfileContent"]) == json.loads(content_v1)

    described = rs.describe_authentication_profiles(
        AuthenticationProfileName=profile_name
    )["AuthenticationProfiles"]
    assert len(described) == 1, described
    assert json.loads(described[0]["AuthenticationProfileContent"]) == json.loads(content_v1)

    codes = {
        "duplicate-create": _err(lambda: rs.create_authentication_profile(
            AuthenticationProfileName=profile_name,
            AuthenticationProfileContent=content_v2,
        )),
    }
    unaffected = rs.describe_authentication_profiles(
        AuthenticationProfileName=profile_name
    )["AuthenticationProfiles"][0]
    assert json.loads(unaffected["AuthenticationProfileContent"]) == json.loads(content_v1), (
        "a rejected duplicate-create must not alter the existing profile's content"
    )

    rs.modify_authentication_profile(
        AuthenticationProfileName=profile_name,
        AuthenticationProfileContent=content_v2,
    )
    after = rs.describe_authentication_profiles(
        AuthenticationProfileName=profile_name
    )["AuthenticationProfiles"][0]
    assert json.loads(after["AuthenticationProfileContent"]) == json.loads(content_v2), (
        "modify must replace the stored content"
    )

    rs.delete_authentication_profile(AuthenticationProfileName=profile_name)
    codes["describe-after-delete"] = _err(lambda: rs.describe_authentication_profiles(
        AuthenticationProfileName=profile_name
    ))
    codes["modify-after-delete"] = _err(lambda: rs.modify_authentication_profile(
        AuthenticationProfileName=profile_name, AuthenticationProfileContent=content_v1
    ))
    expected = {
        "duplicate-create": "AuthenticationProfileAlreadyExistsFault",
        "describe-after-delete": "AuthenticationProfileNotFoundFault",
        "modify-after-delete": "AuthenticationProfileNotFoundFault",
    }
    assert codes == expected, f"authentication-profile contract drift:\n expected={expected}\n observed={codes}"

    restored = rs.create_authentication_profile(
        AuthenticationProfileName=profile_name,
        AuthenticationProfileContent=content_v2,
    )
    assert json.loads(restored["AuthenticationProfileContent"]) == json.loads(content_v2), (
        "the create rejected earlier as a duplicate must succeed once the original profile is gone, "
        "and the name must be reusable after delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
