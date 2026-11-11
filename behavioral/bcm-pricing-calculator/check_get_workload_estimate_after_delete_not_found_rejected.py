"""get-workload-estimate-after-delete-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workload-estimate-after-delete-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-pricing-calculator"]

NOT_FOUND_MESSAGE = "The requested WorkloadEstimate was not found. Check the WorkloadEstimate ID and try again."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWorkloadEstimate and UpdateWorkloadEstimate on a deleted estimate both return
    ResourceNotFoundException; a live one still reads fine."""
    client = ctx.client("bcm-pricing-calculator")
    name = ctx.unique_name("sim2real-we-")
    resource_tags = {"sim2real-owner": "get-workload-estimate-after-delete-not-found-rejected"}

    estimate_id = client.create_workload_estimate(name=name, tags=resource_tags)["id"]
    client.delete_workload_estimate(identifier=estimate_id)

    read_code, read_message = _error_code_and_message(lambda: client.get_workload_estimate(identifier=estimate_id))
    assert read_code == "ResourceNotFoundException", f"expected ResourceNotFoundException on read, got {read_code!r}"
    assert read_message == NOT_FOUND_MESSAGE, f"expected {NOT_FOUND_MESSAGE!r} on read, got {read_message!r}"

    # A mutation on the dead id must fail too, not just the read.
    update_code, update_message = _error_code_and_message(
        lambda: client.update_workload_estimate(identifier=estimate_id, name=name)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on update of deleted estimate, got {update_code!r}"
    )
    assert update_message == NOT_FOUND_MESSAGE, (
        f"expected {NOT_FOUND_MESSAGE!r} on update of deleted estimate, got {update_message!r}"
    )

    # Positive control: a second, live estimate is still readable normally.
    other_name = ctx.unique_name("sim2real-we-")
    other_id = client.create_workload_estimate(name=other_name, tags=resource_tags)["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, other_id))
    got_name = client.get_workload_estimate(identifier=other_id)["name"]
    assert got_name == other_name, f"expected live estimate name {other_name!r}, got {got_name!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
