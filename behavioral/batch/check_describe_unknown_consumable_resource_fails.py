"""describe-unknown-consumable-resource-fails."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-unknown-consumable-resource-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeConsumableResource for a name that does not exist raises ClientException.

    Unlike DescribeJobs (which returns an empty list), the singular
    consumable-resource describe takes a required identifier and 400s on miss.
    """
    bat = ctx.client("batch")

    # Positive control: a real, just-created consumable resource must describe
    # successfully first — otherwise a target that rejects every
    # DescribeConsumableResource call would pass this check for the wrong reason.
    name = ctx.unique_name("sim2real-behav-cr-")
    arn = bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=1,
        resourceType="REPLENISHABLE",
        tags={"sim2real-check": CHECK},
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=arn)))

    control = bat.describe_consumable_resource(consumableResource=name)
    assert control["consumableResourceArn"] == arn, (
        f"expected positive control to describe {arn}, got {control.get('consumableResourceArn')!r}"
    )

    missing = ctx.unique_name("sim2real-behav-" + "cr-missing-")
    code, message = _error(lambda: bat.describe_consumable_resource(consumableResource=missing))
    assert code == "ClientException", (
        f"expected ClientException for unknown consumable resource, got {code!r}"
    )
    # The refusal names the ARN the unknown name resolves to in this account and region.
    missing_arn = arn.rsplit("/", 1)[0] + "/" + missing
    expected_message = f"{missing_arn} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
