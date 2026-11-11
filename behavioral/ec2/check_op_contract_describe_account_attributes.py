"""op-contract-describe-account-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-account-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountAttributes lists default-vpc and supported-platforms and narrows by
    AttributeNames; an unknown name is rejected (InvalidParameter) and DryRun returns
    DryRunOperation."""
    ec2 = ctx.client("ec2")

    full = ec2.describe_account_attributes()["AccountAttributes"]
    names = {a["AttributeName"] for a in full}
    assert "default-vpc" in names, f"expected default-vpc attribute in {names}"
    assert "supported-platforms" in names, f"expected supported-platforms attribute in {names}"
    for attr in full:
        assert isinstance(attr.get("AttributeValues"), list), f"AttributeValues missing/not a list: {attr}"

    filtered = ec2.describe_account_attributes(AttributeNames=["default-vpc"])["AccountAttributes"]
    assert len(filtered) == 1 and filtered[0]["AttributeName"] == "default-vpc", (
        f"filtering by AttributeNames did not narrow the result: {filtered}"
    )

    code, code_msg = _error(lambda: ec2.describe_account_attributes(AttributeNames=["not-a-real-attribute"]))
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code}"
    assert code_msg == "The property 'not-a-real-attribute' is not valid", (
        f"expected the exact InvalidParameter message, got {code_msg!r}"
    )

    code2, code2_msg = _error(lambda: ec2.describe_account_attributes(DryRun=True))
    assert code2 == "DryRunOperation", f"expected DryRunOperation, got {code2}"
    assert code2_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {code2_msg!r}"
    )


def _error(fn):
    """Return the (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
