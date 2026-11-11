"""parameter-tier-upgrade-is-one-way-and-intelligent-tiering-derives-the-tier."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-tier-upgrade-is-one-way-and-intelligent-tiering-derives-the-tier"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_SMALL = "s" * 1024          # comfortably inside the 4 KB standard ceiling
_MID = "m" * 5000            # over 4 KB, under 8 KB: advanced-only
_HUGE = "h" * 9000           # over 8 KB: no tier accepts it
_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")
# AWS's refusal text for an oversize value on the Standard tier, verbatim.
_STANDARD_CEILING_MESSAGE = (
    "Standard tier parameters support a maximum parameter value of 4096 characters. To "
    "create a larger parameter value, upgrade the parameter to use the advanced-parameter "
    "tier. For more information, see "
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/"
    "parameter-store-advanced-parameters.html"
)


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        "the call was expected to be refused but it succeeded; a falsy sentinel here "
        "would let an over-permissive target launder acceptance into a code mismatch"
    )


def _delete_if_present(ssm, name):
    """Teardown for a parameter the check expects AWS to have refused: absent is success."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _call_with_retry(fn, retries=15, delay=2.0):
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


def _poll(probe, predicate, timeout_s=60.0, interval_s=2.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s "
                f"(last observed: {last!r})"
            )
        time.sleep(interval_s)


def _rows(ssm, name):
    """The ParameterMetadata rows DescribeParameters reports for an exact name."""
    found = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found += page["Parameters"]
    return found


def _tier_of(ssm, name):
    rows = _rows(ssm, name)
    assert len(rows) == 1, (
        f"DescribeParameters must report exactly one row for {name!r}, got {rows!r}"
    )
    return rows[0].get("Tier")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Intelligent-Tiering derives Standard or Advanced from the value size, the 4 KB and 8 KB
    ceilings are enforced per tier, and an advanced parameter cannot be reverted to standard.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html
    """

    ssm = ctx.client("ssm")
    # The account-level default tier is never touched: it is an account-global singleton.

    # --- 1a: Intelligent-Tiering with nothing advanced-only -> Standard ----------
    small = _param_name(ctx, "tier-it-small-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=small))
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=small,
            Value=_SMALL,
            Type="String",
            Tier="Intelligent-Tiering",
            Tags=[{"Key": "sim2real", "Value": "parameter-tier"}],
        )
    )
    small_tier = _poll(
        lambda: _tier_of(ssm, small),
        lambda t: t is not None,
        what=f"a tier being reported for {small}",
    )
    assert small_tier == "Standard", (
        "Intelligent-Tiering must resolve a request with no advanced-only option to "
        f"the STANDARD tier, not echo the instruction back; DescribeParameters reports "
        f"Tier {small_tier!r} for a {len(_SMALL)}-byte value"
    )

    # --- 1b: the SAME instruction with a >4 KB value -> Advanced ----------------
    mid = _param_name(ctx, "tier-it-mid-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=mid))
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=mid,
            Value=_MID,
            Type="String",
            Tier="Intelligent-Tiering",
            Tags=[{"Key": "sim2real", "Value": "parameter-tier"}],
        )
    )
    mid_tier = _poll(
        lambda: _tier_of(ssm, mid),
        lambda t: t is not None,
        what=f"a tier being reported for {mid}",
    )
    assert mid_tier == "Advanced", (
        f"a {len(_MID)}-byte value exceeds the 4 KB standard ceiling, so the identical "
        f"Intelligent-Tiering instruction must resolve to the ADVANCED tier; "
        f"DescribeParameters reports {mid_tier!r}"
    )
    assert ssm.get_parameter(Name=mid)["Parameter"]["Value"] == _MID, (
        "the auto-upgraded parameter must serve back every byte it was given; length "
        f"was {len(ssm.get_parameter(Name=mid)['Parameter']['Value'])}, expected "
        f"{len(_MID)}"
    )

    # --- 2a: the same oversize value refused on an EXPLICIT Standard tier -------
    refused = _param_name(ctx, "tier-std-oversize-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=refused))
    std_code, std_message = _error(
        lambda: ssm.put_parameter(
            Name=refused, Value=_MID, Type="String", Tier="Standard"
        )
    )
    assert std_code == "ValidationException", (
        f"a {len(_MID)}-byte value on an explicit Standard tier exceeds the documented "
        f"4 KB standard ceiling and must be refused; got {std_code!r}"
    )
    assert std_message == _STANDARD_CEILING_MESSAGE, std_message
    assert _rows(ssm, refused) == [], (
        f"the refused oversize PutParameter must not have created {refused}; "
        f"DescribeParameters reports {_rows(ssm, refused)!r}"
    )
    # Positive control on the same wiring: the identical value on Advanced lands.
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=refused,
            Value=_MID,
            Type="String",
            Tier="Advanced",
            Tags=[{"Key": "sim2real", "Value": "parameter-tier"}],
        )
    )
    control_tier = _poll(
        lambda: _tier_of(ssm, refused),
        lambda t: t is not None,
        what=f"a tier being reported for {refused}",
    )
    assert control_tier == "Advanced", (
        "the positive control proves the refusal above was about the STANDARD ceiling "
        f"and not about the value itself; the same bytes on Advanced report Tier "
        f"{control_tier!r}"
    )

    # --- 2b: over 8 KB is refused even on Advanced ------------------------------
    huge = _param_name(ctx, "tier-adv-oversize-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, huge))
    huge_code, huge_message = _error(
        lambda: ssm.put_parameter(
            Name=huge, Value=_HUGE, Type="String", Tier="Advanced"
        )
    )
    assert huge_code == "ValidationException", (
        f"a {len(_HUGE)}-byte value exceeds the documented 8 KB advanced ceiling and "
        f"must be refused even on the advanced tier; got {huge_code!r}"
    )
    assert huge_message == (
        "The specified parameter value is too large. Advanced-tier parameters support a "
        "maximum parameter value of 8192 characters."
    ), huge_message
    assert _rows(ssm, huge) == [], (
        f"the refused over-8-KB PutParameter must not have created {huge}; "
        f"DescribeParameters reports {_rows(ssm, huge)!r}"
    )

    # --- 3: the upgrade is one-way ----------------------------------------------
    # `refused` is now an advanced parameter holding a 5 KB value. Downgrading it would
    # truncate that value, which is exactly why the docs say it cannot be done.
    downgrade_code, downgrade_message = _error(
        lambda: ssm.put_parameter(
            Name=refused,
            Value=_SMALL,
            Type="String",
            Tier="Standard",
            Overwrite=True,
        )
    )
    assert downgrade_code == "ValidationException", (
        "an advanced parameter must not be revertible to standard "
        '("you can\'t revert an advanced parameter to a standard parameter"); the '
        f"downgrade returned {downgrade_code!r}"
    )
    assert downgrade_message == (
        "This parameter uses the advanced-parameter tier. You can't downgrade a parameter from "
        "the advanced-parameter tier to the standard-parameter tier. If necessary, you can "
        "delete the advanced parameter and recreate it as a standard parameter. Be aware that "
        "standard parameters have a value limit of 4096 characters."
    ), downgrade_message
    still = _tier_of(ssm, refused)
    assert still == "Advanced", (
        f"the refused downgrade must leave the tier at Advanced, got {still!r}"
    )
    assert ssm.get_parameter(Name=refused)["Parameter"]["Value"] == _MID, (
        "the refused downgrade must leave the stored value untouched; its length is "
        f"{len(ssm.get_parameter(Name=refused)['Parameter']['Value'])}, expected "
        f"{len(_MID)}"
    )
    # Restore: the IDENTICAL Overwrite with Tier="Advanced" must succeed, proving the
    # refusal was about the downgrade and not about the Overwrite.
    restored = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=refused,
            Value=_SMALL,
            Type="String",
            Tier="Advanced",
            Overwrite=True,
        )
    )
    assert restored["Version"] == 2, (
        f"the restoring Overwrite must mint Version 2, got {restored!r}"
    )
    final = _poll(
        lambda: ssm.get_parameter(Name=refused)["Parameter"],
        lambda p: p.get("Version") == 2,
        what=f"version 2 of {refused} becoming readable",
    )
    assert final["Value"] == _SMALL, (
        f"the restored parameter must serve the new value; its length is "
        f"{len(final['Value'])}, expected {len(_SMALL)}"
    )
    assert _tier_of(ssm, refused) == "Advanced", (
        "shrinking an advanced parameter's value must NOT silently demote it to "
        f"standard, got {_tier_of(ssm, refused)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
