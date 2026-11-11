"""parameter-policies-survive-a-value-update-and-only-an-empty-array-clears-them."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-policies-survive-a-value-update-and-only-an-empty-array-clears-them"
GROUP = "state-machine"
SERVICES = ["ssm"]

_MAX_POLICIES = 10  # fixed API constant, per PoliciesLimitExceededException's own docs
_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


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


def _metadata(ssm, name):
    """The single ParameterMetadata DescribeParameters reports for an exact name."""
    found = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found += page["Parameters"]
    assert len(found) == 1, (
        f"DescribeParameters must report exactly one metadata row for {name!r}, got "
        f"{found!r}"
    )
    return found[0]


def _policy_types(meta):
    """The sorted PolicyType values on one ParameterMetadata row."""
    return sorted(p["PolicyType"] for p in meta.get("Policies", []))


def _iso_instant(when):
    """ISO_INSTANT, the format the Expiration policy documents by example."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_instant(s):
    """Parse the round-tripped Timestamp attribute, with or without fractional seconds.

    Parameter Store re-serialises '...38.000Z' as '...38Z', so instants are compared, not bytes.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise AssertionError(f"unparseable ISO_INSTANT Timestamp: {s!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Policies on an advanced parameter survive an Overwrite that sends no Policies and are cleared
    only by the empty-policy sentinel; two Expirations, 11 policies or an unknown type are refused
    with exact errors and create nothing.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html
    """

    ssm = ctx.client("ssm")

    name = _param_name(ctx, "policy-lifecycle-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))

    # 30 days out: expiry is enforced by asynchronous periodic scans and must not fire mid-check.
    expiry = _iso_instant(datetime.now(timezone.utc) + timedelta(days=30))
    expiration = {
        "Type": "Expiration",
        "Version": "1.0",
        "Attributes": {"Timestamp": expiry},
    }
    no_change = {
        "Type": "NoChangeNotification",
        "Version": "1.0",
        "Attributes": {"After": "15", "Unit": "Days"},
    }

    first = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="policy-rev-one",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps([expiration, no_change]),
            Tags=[{"Key": "sim2real", "Value": "parameter-policies"}],
        )
    )
    assert first["Version"] == 1, (
        f"the first PutParameter must mint Version 1, got {first!r}"
    )

    meta = _poll(
        lambda: _metadata(ssm, name),
        lambda m: _policy_types(m) == ["Expiration", "NoChangeNotification"],
        timeout_s=60.0,
        what=f"both policies becoming visible on {name}",
    )
    assert meta["Tier"] == "Advanced", (
        f"a parameter created with policies must be advanced-tier, got "
        f"{meta.get('Tier')!r}"
    )
    stored = {p["PolicyType"]: p for p in meta["Policies"]}
    stored_expiry = json.loads(stored["Expiration"]["PolicyText"])
    assert _parse_instant(stored_expiry["Attributes"]["Timestamp"]) == _parse_instant(expiry), (
        f"the Expiration policy must round-trip the exact instant we sent; "
        f"expected {expiry!r}, got {stored_expiry['Attributes'].get('Timestamp')!r}"
    )
    stored_nochange = json.loads(stored["NoChangeNotification"]["PolicyText"])
    assert stored_nochange["Attributes"] == {"After": "15", "Unit": "Days"}, (
        "the NoChangeNotification attributes must round-trip exactly; got "
        f"{stored_nochange.get('Attributes')!r}"
    )
    for policy_type, policy in stored.items():
        assert policy.get("PolicyStatus") != "Failed", (
            f"a freshly attached {policy_type} policy must not report PolicyStatus "
            f"Failed, got {policy!r}"
        )

    second = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name, Value="policy-rev-two", Type="String", Overwrite=True
        )
    )
    assert second["Version"] == 2, (
        f"the value update must mint Version 2, got {second!r}"
    )
    after_update = _poll(
        lambda: _metadata(ssm, name),
        lambda m: m.get("Version") == 2,
        timeout_s=60.0,
        what=f"DescribeParameters catching up to version 2 of {name}",
    )
    assert _policy_types(after_update) == ["Expiration", "NoChangeNotification"], (
        "an Overwrite that sends no Policies must PRESERVE the existing policies "
        '("All existing policies are preserved until you send new policies or an empty '
        f'policy"); after the update the parameter carries {_policy_types(after_update)!r}'
    )
    preserved = {p["PolicyType"]: p for p in after_update["Policies"]}
    preserved_timestamp = json.loads(preserved["Expiration"]["PolicyText"])["Attributes"][
        "Timestamp"
    ]
    assert _parse_instant(preserved_timestamp) == _parse_instant(expiry), (
        "the preserved Expiration policy must still name the original instant "
        f"{expiry!r}, got {preserved['Expiration']['PolicyText']!r}"
    )
    assert after_update["Tier"] == "Advanced", (
        f"the parameter must still be advanced-tier after the update, got "
        f"{after_update.get('Tier')!r}"
    )

    # `Policies="[]"` leaves policies attached; the user guide's removal sentinel is `[{}]`.
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="policy-rev-three",
            Type="String",
            Overwrite=True,
            Policies="[{}]",
        )
    )
    cleared = _poll(
        lambda: _metadata(ssm, name),
        lambda m: _policy_types(m) == [],
        timeout_s=60.0,
        what=f"the empty policy clearing every policy on {name}",
    )
    assert cleared.get("Policies", []) == [], (
        'Policies="[{}]" must remove every policy; the parameter still carries '
        f"{cleared.get('Policies')!r}"
    )
    assert ssm.get_parameter(Name=name)["Parameter"]["Value"] == "policy-rev-three", (
        "clearing the policies must not disturb the stored value; got "
        f"{ssm.get_parameter(Name=name)['Parameter']['Value']!r}"
    )

    conflicting = _param_name(ctx, "policy-conflict-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=conflicting))
    other_expiry = _iso_instant(datetime.now(timezone.utc) + timedelta(days=45))
    conflict_code, conflict_message = _error(
        lambda: ssm.put_parameter(
            Name=conflicting,
            Value="never",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps(
                [
                    expiration,
                    {
                        "Type": "Expiration",
                        "Version": "1.0",
                        "Attributes": {"Timestamp": other_expiry},
                    },
                ]
            ),
        )
    )
    assert conflict_code == "IncompatiblePolicyException", (
        "two Expiration policies on one parameter must be refused with "
        f"IncompatiblePolicyException, got {conflict_code!r}"
    )
    assert conflict_message == "There can be only one expiration policy", conflict_message
    not_found, not_found_message = _error(lambda: ssm.get_parameter(Name=conflicting))
    assert not_found == "ParameterNotFound", (
        f"a refused PutParameter must not create the parameter; GetParameter("
        f"{conflicting}) returned {not_found!r}"
    )
    assert not_found_message == "", not_found_message
    restored = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=conflicting,
            Value="restored",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps([expiration]),
            Tags=[{"Key": "sim2real", "Value": "parameter-policies"}],
        )
    )
    assert restored["Version"] == 1, (
        f"the restoring PutParameter must mint Version 1, got {restored!r}"
    )
    restored_meta = _poll(
        lambda: _metadata(ssm, conflicting),
        lambda m: _policy_types(m) == ["Expiration"],
        timeout_s=60.0,
        what=f"the single Expiration policy landing on {conflicting}",
    )
    assert _policy_types(restored_meta) == ["Expiration"], (
        f"after the restore the parameter must carry exactly one Expiration policy, "
        f"got {_policy_types(restored_meta)!r}"
    )

    over_quota = _param_name(ctx, "policy-overquota-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, over_quota))
    many = [
        {
            "Type": "ExpirationNotification",
            "Version": "1.0",
            "Attributes": {"Before": str(n + 1), "Unit": "Days"},
        }
        for n in range(_MAX_POLICIES + 1)
    ]
    quota_code, quota_message = _error(
        lambda: ssm.put_parameter(
            Name=over_quota,
            Value="never",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps(many),
        )
    )
    assert quota_code == "PoliciesLimitExceededException", (
        f"{_MAX_POLICIES + 1} policies exceeds the fixed maximum of {_MAX_POLICIES} "
        f"and must be refused with PoliciesLimitExceededException, got {quota_code!r}"
    )
    assert quota_message == (
        f"Number of policies attached to a parameter cannot exceed {_MAX_POLICIES}"
    ), quota_message
    over_quota_absent, over_quota_absent_message = _error(lambda: ssm.get_parameter(Name=over_quota))
    assert over_quota_absent == "ParameterNotFound", (
        f"the over-quota PutParameter must not have created {over_quota}, got "
        f"{over_quota_absent!r}"
    )
    assert over_quota_absent_message == "", over_quota_absent_message

    bad_type = _param_name(ctx, "policy-badtype-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, bad_type))
    type_code, type_message = _error(
        lambda: ssm.put_parameter(
            Name=bad_type,
            Value="never",
            Type="String",
            Tier="Advanced",
            Policies=json.dumps(
                [
                    {
                        "Type": "Sim2RealNotAPolicyType",
                        "Version": "1.0",
                        "Attributes": {"After": "1", "Unit": "Days"},
                    }
                ]
            ),
        )
    )
    assert type_code == "InvalidPolicyTypeException", (
        "an unsupported policy type must be refused with InvalidPolicyTypeException "
        f"(the three supported types are Expiration, ExpirationNotification and "
        f"NoChangeNotification), got {type_code!r}"
    )
    assert type_message == "Policy type Sim2RealNotAPolicyType is not supported.", type_message
    bad_type_absent, bad_type_absent_message = _error(lambda: ssm.get_parameter(Name=bad_type))
    assert bad_type_absent == "ParameterNotFound", (
        f"the unsupported-policy PutParameter must not have created {bad_type}, got "
        f"{bad_type_absent!r}"
    )
    assert bad_type_absent_message == "", bad_type_absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
