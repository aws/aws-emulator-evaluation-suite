"""describe-scheduling-policies-rejects-over-hundred-arns."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "describe-scheduling-policies-rejects-over-hundred-arns"
GROUP = "validation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSchedulingPolicies rejects an arns list longer than 100 entries with
    ClientException; a list of exactly 100 ARNs, including a real scheduling policy's, is
    accepted and returns only the policy that exists."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(name=name)["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    bogus = [f"{arn}-missing-{i}" for i in range(100)]
    over_limit = bogus + [arn]

    code, message, request_id = _error_code(lambda: batch.describe_scheduling_policies(arns=over_limit))
    assert code == "ClientException", f"expected ClientException for 101 ARNs, got {code!r}"
    expected_message = (
        "Error executing request, Exception : Number of scheduling policies should be between "
        f"1 and 100., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: exactly 100 ARNs, one of which is real, is accepted.
    at_limit = bogus[:99] + [arn]
    accepted = batch.describe_scheduling_policies(arns=at_limit)["schedulingPolicies"]
    assert [p["arn"] for p in accepted] == [arn], (
        f"expected only the real scheduling policy back, got {accepted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
