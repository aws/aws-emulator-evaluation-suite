"""op-contract-describeIpamByoasn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamByoasn"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpamByoasn succeeds with the documented list shape (BYOIP ASNs are
    an opt-in, provisioned feature so the list is typically empty in a test
    account) and honors DryRun for its permission-check contract."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_ipam_byoasn()
    assert "Byoasns" in resp, "response missing 'Byoasns' list"
    byoasns = resp["Byoasns"]
    assert isinstance(byoasns, list), f"expected 'Byoasns' to be a list, got {type(byoasns).__name__}"
    for item in byoasns:
        assert "Asn" in item and "State" in item, f"Byoasn item missing 'Asn'/'State': {item!r}"

    code, message = _error(lambda: ec2.describe_ipam_byoasn(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
