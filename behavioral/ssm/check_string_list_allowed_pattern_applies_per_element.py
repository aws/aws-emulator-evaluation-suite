"""string-list-allowed-pattern-applies-per-element."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "string-list-allowed-pattern-applies-per-element"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


# Repeated PutParameter on one name throttles with TooManyUpdates.
def _error_code(fn):
    """Return the (code, status, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _call_with_retry(fn, retries=10, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in _THROTTLE:
                time.sleep(delay)
                continue
            raise
    raise last


def _delete_if_present(ssm, name):
    """Delete a parameter that should have been refused; absent is success."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StringList AllowedPattern applies to each comma-separated element: all-matching values
    are accepted; one bad element is refused (ParameterPatternMismatchException), no new version.
    """

    ssm = ctx.client("ssm")
    pattern = "^[0-9]+$"

    # --- every element matches; the joined string would fail ^[0-9]+$ on its commas ---
    name = _param_name(ctx, "stringlist-pattern-")
    _track_parameter(ctx, ssm, name)
    first = ssm.put_parameter(
        Name=name,
        Value="123,456,789",
        Type="StringList",
        AllowedPattern=pattern,
        Tags=[{"Key": "sim2real", "Value": "stringlist-pattern"}],
    )
    assert first["Version"] == 1, (
        f"a StringList whose every element matches AllowedPattern must be accepted, got {first!r}"
    )
    read_back = ssm.get_parameter(Name=name)["Parameter"]
    assert read_back["Value"] == "123,456,789", (
        f"the accepted StringList must read back byte-exact, got {read_back['Value']!r}"
    )
    assert read_back["Type"] == "StringList", read_back

    # --- break exactly one element of an otherwise-matching list -----------------
    code, status, message = _error_code(
        lambda: ssm.put_parameter(
            Name=name,
            Value="123,abc,789",
            Type="StringList",
            AllowedPattern=pattern,
            Overwrite=True,
        )
    )
    assert code == "ParameterPatternMismatchException", (
        "a StringList with one element ('abc') that fails AllowedPattern, among others that "
        f"pass, must be refused with ParameterPatternMismatchException, got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for the pattern mismatch, got {status!r}"
    expected_message = f"Parameter value, cannot be validated against allowedPattern: {pattern}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # --- effect absent: the refused overwrite burns no version ------------------
    after = ssm.get_parameter(Name=name)["Parameter"]
    assert after["Value"] == "123,456,789", (
        f"the refused overwrite must leave the old value in place, got {after['Value']!r}"
    )
    assert after["Version"] == 1, (
        f"the refused overwrite must not mint a new version, got Version {after['Version']}"
    )

    # --- restore: fixing the one bad element lets the overwrite through ---------
    fixed = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="123,999,789",
            Type="StringList",
            AllowedPattern=pattern,
            Overwrite=True,
        )
    )
    assert fixed["Version"] == 2, (
        f"fixing the one bad element must let the overwrite succeed as Version 2, got {fixed!r}"
    )
    final = ssm.get_parameter(Name=name)["Parameter"]
    assert final["Value"] == "123,999,789", final

    # --- a brand-new StringList with a bad element is refused and created nothing
    never = _param_name(ctx, "stringlist-pattern-never-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, never))
    never_code, never_status, never_message = _error_code(
        lambda: ssm.put_parameter(
            Name=never, Value="1,2,x", Type="StringList", AllowedPattern=pattern
        )
    )
    assert never_code == "ParameterPatternMismatchException", never_code
    assert never_status == 400, never_status
    assert never_message == expected_message, never_message
    never_absent, _, never_absent_message = _error_code(lambda: ssm.get_parameter(Name=never))
    assert never_absent == "ParameterNotFound", (
        f"the refused first-write StringList must not have been created, got {never_absent!r}"
    )
    assert never_absent_message == "", never_absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
