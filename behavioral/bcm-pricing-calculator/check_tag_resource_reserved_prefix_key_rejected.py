"""tag-resource-reserved-prefix-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key using the reserved 'aws:' prefix; a normal key still tags fine."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    estimate_id = client.create_workload_estimate(name=name)["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))
    arn = f"arn:aws:bcm-pricing-calculator::{account_id}:workload-estimate/{estimate_id}"

    code, message = _error_code_and_message(lambda: client.tag_resource(arn=arn, tags={"aws:reserved": "x"}))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "System tags cannot be added/updated by requester"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected tag was never applied.
    tags_after_rejection = client.list_tags_for_resource(arn=arn)["tags"]
    assert tags_after_rejection == {}, f"expected no tags applied, got {tags_after_rejection!r}"

    # Positive control: a normal, non-reserved key tags successfully.
    client.tag_resource(arn=arn, tags={"env": "ok"})
    tags_after_control = client.list_tags_for_resource(arn=arn)["tags"]
    assert tags_after_control == {"env": "ok"}, (
        f"expected {{'env': 'ok'}} after a non-reserved tag, got {tags_after_control!r}"
    )


# ===== helpers =====
def _error_code_and_message(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises, because
    accepting input AWS refuses is a failure in its own right, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
