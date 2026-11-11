"""put-parameter-policies-without-advanced-tier-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-policies-without-advanced-tier-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")
_STANDARD_TIER_MESSAGE = (
    "You can't assign parameter policies to a standard-parameter tier. You must "
    "upgrade the parameter to use the advanced-parameter tier. For more information, "
    "see https://docs.aws.amazon.com/systems-manager/latest/userguide/"
    "parameter-store-advanced-parameters.html"
)


# Repeated PutParameter on one name throttles with TooManyUpdates.
def _error_code(fn):
    """Return the (code, message) of the ClientError fn raises; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
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


def _iso_instant(when):
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


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
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """PutParameter with Policies is refused with one message whether Tier is omitted or Standard,
    creates nothing, and the same policies succeed with Tier="Advanced".

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html
    """

    ssm = ctx.client("ssm")

    expiry = _iso_instant(datetime.now(timezone.utc) + timedelta(days=30))
    policies = json.dumps(
        [{"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": expiry}}]
    )

    # --- break: Tier omitted (defaults to Standard) ------------------------------
    omitted = _param_name(ctx, "policy-tier-omitted-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, omitted))
    omitted_code, omitted_message = _error_code(
        lambda: ssm.put_parameter(Name=omitted, Value="never", Type="String", Policies=policies)
    )
    assert omitted_code == "ValidationException", (
        "Policies with no Tier (defaulting to Standard) must be refused with "
        f"ValidationException, got {omitted_code!r}"
    )
    assert omitted_message == _STANDARD_TIER_MESSAGE, omitted_message
    omitted_absent, omitted_absent_message = _error_code(
        lambda: ssm.get_parameter(Name=omitted)
    )
    assert omitted_absent == "ParameterNotFound", (
        f"the refused PutParameter must not have created {omitted}, got {omitted_absent!r}"
    )
    assert omitted_absent_message == "", omitted_absent_message

    # --- break the same way, but with Tier="Standard" stated explicitly ----------
    explicit = _param_name(ctx, "policy-tier-standard-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, explicit))
    explicit_code, explicit_message = _error_code(
        lambda: ssm.put_parameter(
            Name=explicit, Value="never", Type="String", Tier="Standard", Policies=policies
        )
    )
    assert explicit_code == "ValidationException", (
        "Policies with Tier=\"Standard\" stated explicitly must be refused the same way as "
        f"an omitted tier; got {explicit_code!r}"
    )
    assert explicit_message == omitted_message == _STANDARD_TIER_MESSAGE, (
        "an omitted tier and an explicit Standard tier must produce the IDENTICAL refusal "
        f"message (one rule, not two): omitted={omitted_message!r} explicit={explicit_message!r}"
    )
    explicit_absent, explicit_absent_message = _error_code(
        lambda: ssm.get_parameter(Name=explicit)
    )
    assert explicit_absent == "ParameterNotFound", (
        f"the refused PutParameter must not have created {explicit}, got {explicit_absent!r}"
    )
    assert explicit_absent_message == "", explicit_absent_message

    # --- restore: the IDENTICAL policy set succeeds once Tier="Advanced" is added
    restored = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=explicit,
            Value="now-advanced",
            Type="String",
            Tier="Advanced",
            Policies=policies,
            Tags=[{"Key": "sim2real", "Value": "policy-tier"}],
        )
    )
    assert restored["Version"] == 1, (
        "the restoring PutParameter (same name, same policies, Tier=Advanced) must mint "
        f"Version 1 since the two refusals created nothing; got {restored!r}"
    )
    rows = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [explicit]}]
    ):
        rows += page["Parameters"]
    assert len(rows) == 1, f"expected exactly one metadata row for {explicit!r}, got {rows!r}"
    assert rows[0]["Tier"] == "Advanced", (
        f"the restored parameter must be advanced-tier, got {rows[0].get('Tier')!r}"
    )
    assert [p["PolicyType"] for p in rows[0].get("Policies", [])] == ["Expiration"], (
        f"the restored parameter must carry the Expiration policy, got {rows[0].get('Policies')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
