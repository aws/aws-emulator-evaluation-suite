"""create-hub-content-reference-source-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-hub-content-reference-source-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHubContentReference to a nonexistent public content ARN fails with ValidationException
    'Requested source ARN does not exist.' and leaves the hub's content count at its baseline."""
    sm = ctx.client("sagemaker")

    hub_name = ctx.unique_name("sim2real-hub-")
    sm.create_hub(
        HubName=hub_name,
        HubDescription="sim2real behavioral fidelity check",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_hub(HubName=hub_name))
    _wait_for_hub_in_service(sm, hub_name, timeout_s=60)

    baseline_count = len(
        sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")["HubContentSummaries"]
    )

    real_content_arn = _find_real_public_model_arn(sm)
    if real_content_arn is not None:
        # ListHubContents returns ARNs ending in "/{version}", but SageMakerPublicHubContentArn has no
        # version segment (MinVersion pins it), so the suffix is stripped.
        base_content_arn = real_content_arn.rsplit("/", 1)[0]
        sm.create_hub_content_reference(HubName=hub_name, SageMakerPublicHubContentArn=base_content_arn)
        content_name = base_content_arn.split("/")[-1]
        ctx.on_cleanup(
            lambda: sm.delete_hub_content_reference(
                HubName=hub_name, HubContentType="ModelReference", HubContentName=content_name
            )
        )
        baseline_count += 1
        # The new reference may not be listed by ListHubContents right away, so poll for it; it is
        # catalogued as "ModelReference", distinct from the public hub's "Model" content.
        contents = _wait_for_hub_content_count(sm, hub_name, baseline_count, timeout_s=30)
        assert len(contents) == baseline_count, (
            f"positive control: expected {baseline_count} ModelReference content(s) after "
            f"creating the reference, found {len(contents)}"
        )

    bogus_arn = (
        f"arn:aws:sagemaker:{ctx.region}:aws:hub-content/SageMakerPublicHub/Model/"
        "sim2real-definitely-nonexistent-model"
    )
    code, message = _error_code_and_message(
        lambda: sm.create_hub_content_reference(HubName=hub_name, SageMakerPublicHubContentArn=bogus_arn)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    assert message == "Requested source ARN does not exist.", (
        f"expected message 'Requested source ARN does not exist.', got {message!r}"
    )

    contents_after = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")["HubContentSummaries"]
    assert len(contents_after) == baseline_count, (
        f"effect absent: expected content count to stay at {baseline_count} after the rejected "
        f"reference, found {len(contents_after)}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_hub_in_service(sm, hub_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_hub(HubName=hub_name)["HubStatus"]
        if status == "InService":
            return
        time.sleep(2)
    raise AssertionError(f"hub never reached InService, last status={status}")


def _wait_for_hub_content_count(sm, hub_name: str, expected_count: int, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    contents = []
    while time.monotonic() < deadline:
        contents = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")["HubContentSummaries"]
        if len(contents) == expected_count:
            return contents
        time.sleep(2)
    return contents


def _find_real_public_model_arn(sm):
    try:
        summaries = sm.list_hub_contents(
            HubName="arn:aws:sagemaker:" + sm.meta.region_name + ":aws:hub/SageMakerPublicHub",
            HubContentType="Model",
            MaxResults=1,
        )["HubContentSummaries"]
    except ClientError:
        return None
    if not summaries:
        return None
    return summaries[0]["HubContentArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
