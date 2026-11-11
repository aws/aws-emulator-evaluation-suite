"""expiration-notification-requires-expiration-policy."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expiration-notification-requires-expiration-policy"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")
_MISSING_EXPIRATION_MESSAGE = "Expiration notification policies are missing expiration policy"


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


def _delete_if_present(ssm, name):
    """Teardown for a parameter the check expects AWS to have refused: absent is success."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


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
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _metadata(ssm, name):
    """The single ParameterMetadata DescribeParameters reports for an exact name."""
    found = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found += page["Parameters"]
    assert len(found) == 1, (
        f"DescribeParameters must report exactly one metadata row for {name!r}, got {found!r}"
    )
    return found[0]


def _policy_types(meta):
    return sorted(p["PolicyType"] for p in meta.get("Policies", []))


def _iso_instant(when):
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An ExpirationNotification policy is refused without an Expiration policy, on a fresh
    write and on an Overwrite that drops Expiration (leaving prior policies untouched);
    with Expiration present, two ExpirationNotification policies may coexist."""

    ssm = ctx.client("ssm")
    expiry = _iso_instant(datetime.now(timezone.utc) + timedelta(days=30))
    expiration = {"Type": "Expiration", "Version": "1.0", "Attributes": {"Timestamp": expiry}}
    notif_a = {
        "Type": "ExpirationNotification",
        "Version": "1.0",
        "Attributes": {"Before": "7", "Unit": "Days"},
    }
    notif_b = {
        "Type": "ExpirationNotification",
        "Version": "1.0",
        "Attributes": {"Before": "3", "Unit": "Days"},
    }

    # --- break: ExpirationNotification with no Expiration, on a fresh write -----
    alone = _param_name(ctx, "notif-alone-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, alone))
    alone_code, alone_message = _error_code(
        lambda: ssm.put_parameter(
            Name=alone,
            Value="never",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps([notif_a]),
        )
    )
    assert alone_code == "IncompatiblePolicyException", (
        "an ExpirationNotification with no accompanying Expiration policy must be refused "
        f"with IncompatiblePolicyException, got {alone_code!r}"
    )
    assert alone_message == _MISSING_EXPIRATION_MESSAGE, alone_message
    alone_absent, alone_absent_message = _error_code(lambda: ssm.get_parameter(Name=alone))
    assert alone_absent == "ParameterNotFound", (
        f"the refused PutParameter must not have created {alone}, got {alone_absent!r}"
    )
    assert alone_absent_message == "", alone_absent_message

    # --- positive: Expiration plus ONE ExpirationNotification succeeds ----------
    name = _param_name(ctx, "notif-lifecycle-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    first = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="v1",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps([expiration, notif_a]),
            Tags=[{"Key": "sim2real", "Value": "expiration-notification"}],
        )
    )
    assert first["Version"] == 1, first
    meta = _poll(
        lambda: _metadata(ssm, name),
        lambda m: _policy_types(m) == ["Expiration", "ExpirationNotification"],
        what=f"both policies becoming visible on {name}",
    )
    stored = {p["PolicyType"]: json.loads(p["PolicyText"]) for p in meta["Policies"]}
    assert stored["ExpirationNotification"]["Attributes"] == {"Before": "7", "Unit": "Days"}, (
        f"the ExpirationNotification attributes must round-trip exactly, got "
        f"{stored['ExpirationNotification']['Attributes']!r}"
    )

    # --- positive: a SECOND, distinct ExpirationNotification can coexist --------
    second = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="v2",
            Type="String",
            Tier="Advanced",
            Overwrite=True,
            Policies=json.dumps([expiration, notif_a, notif_b]),
        )
    )
    assert second["Version"] == 2, second
    meta2 = _poll(
        lambda: _metadata(ssm, name),
        lambda m: _policy_types(m) == ["Expiration", "ExpirationNotification", "ExpirationNotification"],
        what=f"all three policies becoming visible on {name}",
    )
    befores = sorted(
        json.loads(p["PolicyText"])["Attributes"]["Before"]
        for p in meta2["Policies"]
        if p["PolicyType"] == "ExpirationNotification"
    )
    assert befores == ["3", "7"], (
        f"both ExpirationNotification policies must be stored distinctly, got Before={befores!r}"
    )
    assert (
        sum(1 for p in meta2["Policies"] if p["PolicyType"] == "Expiration") == 1
    ), f"exactly one Expiration policy must remain, got {meta2['Policies']!r}"

    # --- break: an Overwrite that DROPS Expiration, leaving notifications behind
    drop_code, drop_message = _error_code(
        lambda: ssm.put_parameter(
            Name=name,
            Value="v3",
            Type="String",
            Tier="Advanced",
            Overwrite=True,
            Policies=json.dumps([notif_a, notif_b]),
        )
    )
    assert drop_code == "IncompatiblePolicyException", (
        "an Overwrite that keeps the ExpirationNotification policies but drops the "
        f"Expiration policy must be refused the same way as a fresh orphaned write; got "
        f"{drop_code!r}"
    )
    assert drop_message == _MISSING_EXPIRATION_MESSAGE, drop_message

    # --- effect absent: the refused overwrite must not touch the ledger ---------
    after = ssm.get_parameter(Name=name)["Parameter"]
    assert (after["Value"], after["Version"]) == ("v2", 2), (
        "the refused Overwrite must leave the parameter at its last valid state (v2, "
        f"Version 2), got value={after['Value']!r} version={after['Version']}"
    )
    after_meta = _metadata(ssm, name)
    assert _policy_types(after_meta) == [
        "Expiration",
        "ExpirationNotification",
        "ExpirationNotification",
    ], (
        "the refused Overwrite must leave all three prior policies in place, got "
        f"{_policy_types(after_meta)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
