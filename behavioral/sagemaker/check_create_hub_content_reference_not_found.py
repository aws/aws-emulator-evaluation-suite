"""create-hub-content-reference-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-hub-content-reference-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHubContentReference to a well-formed nonexistent public content ARN fails with
    ValidationException 'Requested source ARN does not exist.' and records no reference beyond the
    baseline, while the hub stays InService."""
    sm = ctx.client("sagemaker")
    hub_name = ctx.unique_name("sim2real-behav-hub-")

    sm.create_hub(
        HubName=hub_name,
        HubDescription="sim2real behavioral fidelity check hub",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_hub(HubName=hub_name))
    _wait_for_hub_in_service(ctx, hub_name)

    baseline_count = len(
        sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")["HubContentSummaries"]
    )

    real_content_arn = _find_real_public_model_arn(sm)
    if real_content_arn is not None:
        # ListHubContents' HubContentArn carries a trailing "/{version}" that
        # CreateHubContentReference's SageMakerPublicHubContentArn pattern rejects -- strip it.
        base_content_arn = real_content_arn.rsplit("/", 1)[0]
        sm.create_hub_content_reference(HubName=hub_name, SageMakerPublicHubContentArn=base_content_arn)
        content_name = base_content_arn.split("/")[-1]
        ctx.on_cleanup(
            lambda: sm.delete_hub_content_reference(
                HubName=hub_name, HubContentType="ModelReference", HubContentName=content_name
            )
        )
        baseline_count += 1
        refs_after_control = _wait_for_hub_content_count(sm, hub_name, baseline_count)
        assert len(refs_after_control) == baseline_count, (
            f"positive control: expected {baseline_count} ModelReference(s) after referencing "
            f"real public hub content, found {len(refs_after_control)}"
        )

    bogus_public_arn = (
        f"arn:aws:sagemaker:{ctx.region}:aws:hub-content/SageMakerPublicHub/Model/"
        "sim2real-behav-model-that-does-not-exist"
    )

    code, message = _error_code_and_message(
        lambda: sm.create_hub_content_reference(
            HubName=hub_name, SageMakerPublicHubContentArn=bogus_public_arn
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message!r})"
    assert message == "Requested source ARN does not exist.", (
        f"expected message 'Requested source ARN does not exist.', got {message!r}"
    )

    # Effect absent: the bogus reference added nothing beyond the positive control's own count.
    refs = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")[
        "HubContentSummaries"
    ]
    assert len(refs) == baseline_count, (
        f"expected {baseline_count} hub content reference(s), found {len(refs)}: {refs}"
    )

    # Terminal control: the hub itself is real and describable (the failure above was
    # specifically about the missing public content, not about the hub being broken).
    desc = sm.describe_hub(HubName=hub_name)
    assert desc["HubName"] == hub_name
    assert desc["HubStatus"] == "InService"


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_hub_in_service(ctx, hub_name, timeout_s=60.0, interval_s=3.0):
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_hub(HubName=hub_name)["HubStatus"]
        if status == "InService":
            return
        if status == "CreateFailed":
            raise AssertionError(f"hub {hub_name} entered CreateFailed while provisioning")
        time.sleep(interval_s)
    raise AssertionError(f"hub {hub_name} never reached InService, last status={status}")


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


def _wait_for_hub_content_count(sm, hub_name, expected_count, timeout_s=30.0, interval_s=2.0):
    # CreateHubContentReference returns before the new content is necessarily visible in
    # ListHubContents (eventual consistency) -- poll for it rather than asserting immediately.
    deadline = time.monotonic() + timeout_s
    contents = []
    while time.monotonic() < deadline:
        contents = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")[
            "HubContentSummaries"
        ]
        if len(contents) == expected_count:
            return contents
        time.sleep(interval_s)
    raise AssertionError(
        f"hub {hub_name} never reached {expected_count} ModelReference(s), "
        f"last saw {len(contents)}: {contents}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
