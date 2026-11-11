"""op-contract-describeAccountLimits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeAccountLimits"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits reports a positive StackLimit; an unrecognized
    NextToken is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")

    resp = cfn.describe_account_limits()
    limits = resp["AccountLimits"]
    assert isinstance(limits, list) and len(limits) > 0, (
        f"expected a non-empty AccountLimits list, got {limits!r}"
    )
    by_name = {item["Name"]: item["Value"] for item in limits}
    assert "StackLimit" in by_name, f"expected a StackLimit entry, got names {sorted(by_name)}"
    assert isinstance(by_name["StackLimit"], int) and by_name["StackLimit"] > 0, (
        f"expected a positive int StackLimit, got {by_name['StackLimit']!r}"
    )

    bogus_token = "sim2real-bogus-next-token-0000"
    code, message = _error(lambda: cfn.describe_account_limits(NextToken=bogus_token))
    assert code == "ValidationError", f"expected ValidationError for bogus NextToken, got {code}"
    assert message == f"{bogus_token} is not a valid NextToken", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
