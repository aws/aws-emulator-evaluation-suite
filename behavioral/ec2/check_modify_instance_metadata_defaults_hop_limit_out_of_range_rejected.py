"""modify-instance-metadata-defaults-hop-limit-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-metadata-defaults-hop-limit-out-of-range-rejected"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """ModifyInstanceMetadataDefaults rejects an out-of-range hop limit and leaves the prior value intact."""
    ec2 = ctx.client("ec2")

    original = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "instance metadata defaults are managed by a declarative policy in this account "
            "and cannot be modified directly by ModifyInstanceMetadataDefaults"
        )

    original_http_tokens = original.get("HttpTokens", "no-preference")
    original_hop_limit = original.get("HttpPutResponseHopLimit") or -1
    original_http_endpoint = original.get("HttpEndpoint", "no-preference")
    original_metadata_tags = original.get("InstanceMetadataTags", "no-preference")
    original_tokens_enforced = original.get("HttpTokensEnforced", "no-preference")

    def _restore():
        ec2.modify_instance_metadata_defaults(
            HttpTokens=original_http_tokens,
            HttpPutResponseHopLimit=original_hop_limit,
            HttpEndpoint=original_http_endpoint,
            InstanceMetadataTags=original_metadata_tags,
            HttpTokensEnforced=original_tokens_enforced,
        )

    ctx.on_cleanup(_restore)

    # Positive control: a valid hop limit (documented range is 1-64, or -1 for no preference).
    ec2.modify_instance_metadata_defaults(HttpTokens="required", HttpPutResponseHopLimit=5)
    current = _poll_until(
        lambda: ec2.get_instance_metadata_defaults()["AccountLevel"],
        lambda al: al.get("HttpPutResponseHopLimit") == 5,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert current.get("HttpPutResponseHopLimit") == 5, current

    # Negative: 100 is outside the documented 1-64 (or -1) range.
    code, message = _error(
        lambda: ec2.modify_instance_metadata_defaults(HttpPutResponseHopLimit=100)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for HttpPutResponseHopLimit. Expecting 1-64, or -1 for no-preference.", message

    # Effect absent: the out-of-range attempt must not have changed the stored value.
    after = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert after.get("HttpPutResponseHopLimit") == 5, (
        f"rejected ModifyInstanceMetadataDefaults call still changed the account setting: {after}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
