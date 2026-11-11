"""allowed-pattern-rejected-overwrite-burns-no-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "allowed-pattern-rejected-overwrite-burns-no-version"
GROUP = 'overly-permissive'
SERVICES = ['ssm']


# Repeated PutParameter on one name throttles with TooManyUpdates, hence _call_with_retry.
def _error_code(fn):
    """(code, HTTP status, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return error.get("Code"), status, error.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
            if exc.response.get("Error", {}).get("Code") in (
                "TooManyUpdates",
                "ThrottlingException",
            ):
                time.sleep(delay)
                continue
            raise
    raise last


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutParameter overwrite refused for an AllowedPattern violation burns no version and adds no
    history entry, the parameter stays writable, and a replacement pattern is stored and
    enforced."""

    ssm = ctx.client("ssm")

    numeric = "^[0-9]+$"
    name = _param_name(ctx, "pattern-")
    _track_parameter(ctx, ssm, name)

    created = ssm.put_parameter(
        Name=name, Value="123", Type="String", AllowedPattern=numeric
    )
    assert created["Version"] == 1, created

    # The pattern must be stored against the version, not merely honoured in-flight.
    first_history = ssm.get_parameter_history(Name=name)["Parameters"]
    assert len(first_history) == 1, first_history
    assert first_history[0].get("AllowedPattern") == numeric, (
        "GetParameterHistory must report the AllowedPattern stored with the version, got "
        f"{first_history[0].get('AllowedPattern')!r}"
    )

    # --- control: a conforming overwrite advances the ledger ----------------
    ok = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name, Value="456", Type="String", AllowedPattern=numeric, Overwrite=True
        )
    )
    assert ok["Version"] == 2, f"a conforming overwrite must mint Version 2, got {ok}"

    # --- break exactly one thing: the value no longer matches the pattern ---
    code, status, message = _error_code(
        lambda: ssm.put_parameter(
            Name=name, Value="abc", Type="String", AllowedPattern=numeric, Overwrite=True
        )
    )
    assert code == "ParameterPatternMismatchException", (
        "an overwrite whose value violates AllowedPattern must be refused with "
        f"ParameterPatternMismatchException, got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for the pattern mismatch, got {status!r}"
    expected_message = f"Parameter value, cannot be validated against allowedPattern: {numeric}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # --- effect absent, across the whole version ledger ---------------------
    after = ssm.get_parameter(Name=name)["Parameter"]
    assert after["Value"] == "456", (
        f"the rejected overwrite must not change the value, got {after['Value']!r}"
    )
    assert after["Version"] == 2, (
        f"a rejected overwrite must not burn a version, got Version {after['Version']}"
    )
    history = sorted(
        ssm.get_parameter_history(Name=name)["Parameters"], key=lambda h: h["Version"]
    )
    assert [h["Version"] for h in history] == [1, 2], (
        f"history must be exactly versions [1, 2], got {[h['Version'] for h in history]}"
    )
    assert [h["Value"] for h in history] == ["123", "456"], (
        f"the refused value must appear nowhere in history, got {[h['Value'] for h in history]}"
    )
    v3_code, v3_status, v3_message = _error_code(lambda: ssm.get_parameter(Name=f"{name}:3"))
    assert v3_code == "ParameterVersionNotFound", (
        f"version 3 must not be resolvable after a rejected overwrite, got {v3_code!r}"
    )
    assert v3_status == 400, f"expected HTTP 400 for ParameterVersionNotFound, got {v3_status!r}"
    # The message names the parameter without its leading '/'.
    expected_message = f"Systems Manager could not find version 3 of {name.lstrip('/')}. Verify the version and try again."
    assert v3_message == expected_message, f"expected the message {expected_message!r}, got {v3_message!r}"

    # --- control: the parameter is not wedged, and numbering resumes at 3 ---
    resumed = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name, Value="789", Type="String", AllowedPattern=numeric, Overwrite=True
        )
    )
    assert resumed["Version"] == 3, (
        f"the next legal overwrite must mint Version 3, not 4; got {resumed}"
    )
    final = ssm.get_parameter(Name=name)["Parameter"]
    assert (final["Value"], final["Version"]) == ("789", 3), final

    # --- the stored pattern can be replaced, and the new one is enforced ----
    lowercase = "^[a-z-]+$"
    relaxed = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="now-letters-are-fine",
            Type="String",
            AllowedPattern=lowercase,
            Overwrite=True,
        )
    )
    assert relaxed["Version"] == 4, relaxed
    latest = ssm.get_parameter(Name=name)["Parameter"]
    assert latest["Value"] == "now-letters-are-fine", latest
    replaced = [
        h
        for h in ssm.get_parameter_history(Name=name)["Parameters"]
        if h["Version"] == 4
    ]
    assert len(replaced) == 1 and replaced[0].get("AllowedPattern") == lowercase, (
        "the replacement AllowedPattern must be stored against version 4, got "
        f"{[h.get('AllowedPattern') for h in replaced]}"
    )
    # A value that satisfied only the OLD pattern is now refused, proving the
    # replacement is live rather than cosmetic.
    stale, stale_status, stale_message = _error_code(
        lambda: ssm.put_parameter(
            Name=name,
            Value="123",
            Type="String",
            AllowedPattern=lowercase,
            Overwrite=True,
        )
    )
    assert stale == "ParameterPatternMismatchException", (
        "after the pattern is replaced, a value matching only the old pattern must be "
        f"refused, got {stale!r}"
    )
    assert stale_status == 400, f"expected HTTP 400 for the second pattern mismatch, got {stale_status!r}"
    assert stale_message, "expected a non-empty ParameterPatternMismatchException message"
    assert ssm.get_parameter(Name=name)["Parameter"]["Version"] == 4, (
        "the second rejection must also burn no version"
    )
    assert (
        len(ssm.get_parameter_history(Name=name)["Parameters"]) == 4
    ), "two rejections plus four accepted writes must leave exactly 4 history entries"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
