"""create-hub-content-reference-missing-hub-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-hub-content-reference-missing-hub-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHubContentReference on a never-created hub with a nonexistent public content ARN fails with
    ValidationException and the exact source-ARN message and creates no hub (DescribeHub:
    ResourceNotFound), while DescribeHub on a real private hub returns it."""
    sm = ctx.client("sagemaker")
    missing_hub_name = ctx.unique_name("sim2real-hub-missing-")
    fake_public_content_arn = (
        f"arn:aws:sagemaker:{ctx.region}:aws:hub-content/SageMakerPublicHub/Model/"
        "sim2real-nonexistent-model-id"
    )

    # positive control: a real hub of ours resolves fine via the Hub API
    real_hub_name = ctx.unique_name("sim2real-hub-real-")
    sm.create_hub(
        HubName=real_hub_name,
        HubDescription="sim2real behavioral check hub",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_hub(sm, real_hub_name))
    described = sm.describe_hub(HubName=real_hub_name)
    assert described["HubName"] == real_hub_name

    # breaking two things at once (missing hub, missing public content): the
    # content-ARN validation fires first, so the rejection is ValidationException,
    # not the ResourceNotFound a missing hub alone (with valid content) gets.
    code, message = _error_code_and_message(
        lambda: sm.create_hub_content_reference(
            HubName=missing_hub_name,
            SageMakerPublicHubContentArn=fake_public_content_arn,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    expected = "Requested source ARN does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: still no such hub was created
    hub_describe_code, hub_describe_message = _error_code_and_message(
        lambda: sm.describe_hub(HubName=missing_hub_name)
    )
    assert hub_describe_code == "ResourceNotFound", hub_describe_code
    expected_describe = f"Hub with name {missing_hub_name} does not exist."
    assert hub_describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {hub_describe_message!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _safe_delete_hub(sm, name):
    import time

    # A hub that is still being created answers DeleteHub with ResourceInUse.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            sm.delete_hub(HubName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
