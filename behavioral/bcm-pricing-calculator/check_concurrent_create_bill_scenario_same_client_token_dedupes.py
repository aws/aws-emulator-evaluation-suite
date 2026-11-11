"""concurrent-create-bill-scenario-same-client-token-dedupes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-bill-scenario-same-client-token-dedupes"
GROUP = "concurrency"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """From an AWS Organizations member account, every concurrent CreateBillScenario racer sharing one
    client token gets the identical member-account ValidationException, and ListBillScenarios is
    refused too, so no racer can leave a discoverable bill scenario behind."""
    client = ctx.client("bcm-pricing-calculator")

    from botocore.exceptions import ClientError

    # Positive control: the account and credentials are otherwise healthy for this service, so the
    # refusal below is a targeted management-account gate, not a blanket permissions failure.
    control_name = ctx.unique_name("sim2real-we-")
    control = client.create_workload_estimate(name=control_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, control["id"]))
    control_read = client.get_workload_estimate(identifier=control["id"])
    assert control_read["name"] == control_name, f"expected {control_name!r}, got {control_read['name']!r}"

    token = ctx.unique_name("sim2real-tok-")
    name = ctx.unique_name("sim2real-bs-")
    racer_count = 5

    def _create():
        try:
            client.create_bill_scenario(name=name, clientToken=token)
            return None
        except ClientError as err:
            return err.response["Error"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        errors = list(pool.map(lambda _i: _create(), range(racer_count)))

    assert all(e is not None for e in errors), (
        "expected every racer to be refused (this account is a member account), but at least one "
        f"create_bill_scenario call succeeded: {errors}"
    )
    codes = {e["Code"] for e in errors}
    assert codes == {"ValidationException"}, f"expected ValidationException from every racer, got {codes}"
    messages = {e["Message"] for e in errors}
    assert messages == {
        "Operation not permitted for member accounts. This API is only allowed for regular or payer accounts."
    }, f"expected the identical member-account refusal from every racer, got {messages}"

    # The terminal read is independent, at the destination — a different operation than the one
    # that was refused above. ListBillScenarios turns out to be gated identically: the withdrawal
    # covers reads too, so there is no way, from this account, to discover a bill scenario the
    # refused racers might have left.
    try:
        client.list_bill_scenarios(filters=[{"name": "NAME", "values": [name]}])
        raise AssertionError("expected ListBillScenarios to be refused for a member account, but it succeeded")
    except ClientError as err:
        list_error = err.response["Error"]
    assert list_error["Code"] == "ValidationException", f"expected ValidationException, got {list_error['Code']!r}"
    assert list_error["Message"] == (
        "Operation not permitted for member accounts. This API is only allowed for regular or payer accounts."
    ), f"expected the identical member-account refusal, got {list_error['Message']!r}"


# ===== helpers =====
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
