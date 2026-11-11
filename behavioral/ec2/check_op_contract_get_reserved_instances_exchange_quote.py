"""op-contract-get-reserved-instances-exchange-quote."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-reserved-instances-exchange-quote"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReservedInstancesExchangeQuote rejects an unknown Convertible Reserved Instance id with
    InvalidReservedInstanceId and its exact message; for an active convertible RI the account already
    owns, the quote carries IsValidExchange, ReservedInstanceValueSet and (when valid) CurrencyCode."""
    ec2 = ctx.client("ec2")

    # error boundary: RI IDs are UUID-shaped, not prefixed like other EC2 resources.
    bogus_ri_id = "12345678-1234-1234-1234-123456789012"
    code, message = _client_error(lambda: ec2.get_reserved_instances_exchange_quote(
        ReservedInstanceIds=[bogus_ri_id]
    ))
    assert code == "InvalidReservedInstanceId", f"unexpected error code: {code}"
    expected_message = f" [{bogus_ri_id}]"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # success-path contract, opportunistically: only if the account already owns an
    # active Convertible Reserved Instance (this check never purchases one -- that is
    # real money and a real multi-month/year commitment, unlike every other resource
    # this suite creates and deletes within seconds). Absence is not a failure -- the
    # error-boundary assertion above is this check's always-testable, mandatory contract;
    # this block only adds evidence when the account happens to have a real RI to exercise.
    owned = ec2.describe_reserved_instances(Filters=[
        {"Name": "state", "Values": ["active"]},
        {"Name": "offering-class", "Values": ["convertible"]},
    ])["ReservedInstances"]
    if owned:
        quote = ec2.get_reserved_instances_exchange_quote(ReservedInstanceIds=[owned[0]["ReservedInstancesId"]])
        assert "IsValidExchange" in quote
        assert "CurrencyCode" in quote or not quote["IsValidExchange"]
        assert "ReservedInstanceValueSet" in quote


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
