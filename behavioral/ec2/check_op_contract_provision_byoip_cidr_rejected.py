"""op-contract-provision-byoip-cidr-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-provision-byoip-cidr-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ProvisionByoipCidr fails with InvalidParameterValue for a malformed CIDR and with MissingParameter
    for a valid CIDR without CidrAuthorizationContext, each with its exact message, and
    DescribeByoipCidrs lists the same CIDRs before and after."""
    ec2 = ctx.client("ec2")

    # positive control: the account and credentials are healthy for BYOIP reads before either
    # rejection is exercised, so a universally-denied account cannot pass by accident.
    baseline = ec2.describe_byoip_cidrs(MaxResults=10)
    assert baseline["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from DescribeByoipCidrs, got {baseline['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "ByoipCidrs" in baseline, f"expected a ByoipCidrs list, got keys {sorted(baseline)}"
    existing_cidrs = {c["Cidr"] for c in baseline["ByoipCidrs"]}

    err, message, _ = _client_error(lambda: ec2.provision_byoip_cidr(Cidr="999.999.999.0/24"))
    assert err == "InvalidParameterValue", f"expected InvalidParameterValue, got {err}"
    assert message == "The CIDR (999.999.999.0/24) is not valid.", f"unexpected InvalidParameterValue message: {message!r}"

    err2, message2, _ = _client_error(lambda: ec2.provision_byoip_cidr(Cidr="198.51.100.0/24"))
    assert err2 == "MissingParameter", f"expected MissingParameter, got {err2}"
    assert message2 == "You must provide a CidrAuthorizationContext parameter.", f"unexpected MissingParameter message: {message2!r}"

    # independent read at the destination: neither rejected call left a trace in the inventory
    after = ec2.describe_byoip_cidrs(MaxResults=10)
    assert "ByoipCidrs" in after, f"expected a ByoipCidrs list, got keys {sorted(after)}"
    after_cidrs = {c["Cidr"] for c in after["ByoipCidrs"]}
    assert after_cidrs == existing_cidrs, (
        f"rejected ProvisionByoipCidr calls must not appear in the BYOIP inventory, "
        f"found new entries {after_cidrs - existing_cidrs}"
    )


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
