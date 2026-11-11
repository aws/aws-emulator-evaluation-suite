"""instance-metadata-defaults-invalid-hop-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "instance-metadata-defaults-invalid-hop-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """ModifyInstanceMetadataDefaults sets an in-range HttpPutResponseHopLimit that
    GetInstanceMetadataDefaults reads back, then rejects an out-of-range one with
    InvalidParameterValue and its exact message, leaving the read-back value unchanged.
    """
    ec2 = ctx.client("ec2")

    original = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "instance metadata defaults are managed by a declarative policy in this "
            "account and cannot be modified directly by ModifyInstanceMetadataDefaults"
        )
    original_hop_limit = original.get("HttpPutResponseHopLimit") or -1
    ctx.on_cleanup(
        lambda: ec2.modify_instance_metadata_defaults(
            HttpPutResponseHopLimit=original_hop_limit
        )
    )

    control_hop_limit = 5
    ec2.modify_instance_metadata_defaults(HttpPutResponseHopLimit=control_hop_limit)
    landed = _poll_until(
        lambda: ec2.get_instance_metadata_defaults()["AccountLevel"].get(
            "HttpPutResponseHopLimit"
        ),
        lambda v: v == control_hop_limit,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert landed == control_hop_limit, (
        f"positive control did not land: expected {control_hop_limit}, got {landed}"
    )

    code, message = _error(
        lambda: ec2.modify_instance_metadata_defaults(HttpPutResponseHopLimit=999)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "Invalid value for HttpPutResponseHopLimit. Expecting 1-64, or -1 for no-preference."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = ec2.get_instance_metadata_defaults()["AccountLevel"].get(
        "HttpPutResponseHopLimit"
    )
    assert after == control_hop_limit, (
        f"rejected ModifyInstanceMetadataDefaults call still changed the account "
        f"setting: expected {control_hop_limit}, got {after}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
