"""bill-scenario-create-get-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bill-scenario-create-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["bcm-pricing-calculator"]

MEMBER_REFUSAL = (
    "Operation not permitted for member accounts. This API is only allowed for regular or payer accounts."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From an AWS Organizations member account, CreateBillScenario and ListBillScenarios both get the
    member-account ValidationException, while CreateWorkloadEstimate on the same client succeeds,
    so the refusal is specific to the BillScenario surface."""
    client = ctx.client("bcm-pricing-calculator")
    name = ctx.unique_name("sim2real-bs-")

    # Positive control: a different create on the same client succeeds, so the refusals
    # below are specific to the BillScenario subject and not a blanket account/credential problem.
    estimate_name = ctx.unique_name("sim2real-we-")
    estimate = client.create_workload_estimate(
        name=estimate_name, tags={"sim2real-owner": "bill-scenario-create-get-delete-lifecycle"}
    )
    estimate_id = estimate["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))
    assert estimate["name"] == estimate_name, f"expected {estimate_name!r}, got {estimate.get('name')!r}"

    # The specific refusal on the mutating call.
    create_code, create_message = _member_account_refusal(lambda: client.create_bill_scenario(name=name))
    assert create_code == "ValidationException", f"expected ValidationException, got {create_code!r}"
    assert create_message == MEMBER_REFUSAL, f"expected {MEMBER_REFUSAL!r}, got message={create_message!r}"

    # Independent read, at the destination: it is refused identically, not merely empty --
    # the BillScenario subject as a whole is gated, not just this one create shape.
    list_code, list_message = _member_account_refusal(lambda: client.list_bill_scenarios())
    assert list_code == "ValidationException", f"expected ValidationException, got {list_code!r}"
    assert list_message == MEMBER_REFUSAL, f"expected {MEMBER_REFUSAL!r}, got message={list_message!r}"


# ===== helpers =====
def _member_account_refusal(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
        raise AssertionError(f"expected a member-account refusal, call succeeded with {result!r}")
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")


def _delete_workload_estimate(client, estimate_id):
    from botocore.exceptions import ClientError

    try:
        client.delete_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
