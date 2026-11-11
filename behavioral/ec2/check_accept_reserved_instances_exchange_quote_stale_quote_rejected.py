"""accept-reserved-instances-exchange-quote-stale-quote-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accept-reserved-instances-exchange-quote-stale-quote-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReservedInstancesExchangeQuote and AcceptReservedInstancesExchangeQuote refuse an unknown Convertible
    Reserved Instance id with the same InvalidReservedInstanceId code and exact message (Accept re-validates the
    ids), while Accept under DryRun answers DryRunOperation with its exact message.
    """
    ec2 = ctx.client("ec2")
    bogus_id = str(uuid.uuid4())

    get_info = _error_info(
        lambda: ec2.get_reserved_instances_exchange_quote(ReservedInstanceIds=[bogus_id])
    )
    assert get_info["code"] == "InvalidReservedInstanceId", (
        f"expected InvalidReservedInstanceId, got {get_info['code']!r}"
    )
    expected_message = f" [{bogus_id}]"
    assert get_info["message"] == expected_message, (
        f"expected message {expected_message!r}, got {get_info['message']!r}"
    )

    accept_info = _error_info(
        lambda: ec2.accept_reserved_instances_exchange_quote(ReservedInstanceIds=[bogus_id])
    )
    assert accept_info == get_info, (
        "AcceptReservedInstancesExchangeQuote did not independently re-validate the "
        f"reservation id the same way Get did (Get={get_info!r}, Accept={accept_info!r})"
    )

    # Effect absent: no exchange was ever created for the bogus id.
    # (Both calls raised before returning an ExchangeId/quote, so there is
    # nothing further to observe -- the point is that neither one succeeded.)

    # Positive control: DryRun proves permission is granted before any id is
    # resolved -- it returns DryRunOperation even for a
    # made-up OfferingId, so this needs no real offering or owned RI.
    fake_offering_id = str(uuid.uuid4())
    dry_run = _error_info(
        lambda: ec2.accept_reserved_instances_exchange_quote(
            ReservedInstanceIds=[bogus_id],
            TargetConfigurations=[{"OfferingId": fake_offering_id}],
            DryRun=True,
        )
    )
    assert dry_run["code"] == "DryRunOperation", (
        f"expected DryRunOperation (proving Accept is otherwise permitted), got {dry_run['code']!r}"
    )
    assert dry_run["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {dry_run['message']!r}"
    )


def _error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
