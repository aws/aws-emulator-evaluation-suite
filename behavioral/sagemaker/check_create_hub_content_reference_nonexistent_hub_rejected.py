"""create-hub-content-reference-nonexistent-hub-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-hub-content-reference-nonexistent-hub-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHubContentReference pointing at a non-existent Hub is rejected with
    ResourceNotFound rather than creating an orphaned reference, even though the referenced
    public hub content ARN itself is perfectly valid.
    """
    sm = ctx.client("sagemaker")

    public_content_arn = _pick_public_model_content_arn(sm)

    # --- negative: the Hub named here was never created ---
    missing_hub_name = ctx.unique_name("sim2real-hub-missing-")
    code, message = _error_code_and_message(
        lambda: sm.create_hub_content_reference(
            HubName=missing_hub_name, SageMakerPublicHubContentArn=public_content_arn
        )
    )
    expected_message = f"Hub with name {missing_hub_name} does not exist."
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no such hub was implicitly created, and no reference exists under it
    describe_code, describe_message = _error_code_and_message(lambda: sm.describe_hub(HubName=missing_hub_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}"
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    # --- positive control: the same content ARN, referenced from a real, existing Hub, succeeds ---
    hub_name = ctx.unique_name("sim2real-hub-")
    sm.create_hub(
        HubName=hub_name,
        HubDescription="sim2real behavioral check hub",
        S3StorageConfig={},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_hub(HubName=hub_name))
    _wait_for_hub_in_service(sm, hub_name, timeout_s=120)

    resp = sm.create_hub_content_reference(HubName=hub_name, SageMakerPublicHubContentArn=public_content_arn)
    content_name = resp["HubContentArn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(
        lambda: sm.delete_hub_content_reference(
            HubName=hub_name, HubContentType="ModelReference", HubContentName=content_name
        )
    )
    assert resp["HubArn"].endswith(f"hub/{hub_name}"), f"unexpected HubArn {resp['HubArn']!r}"

    # terminal read: independent of the mutating call -- the reference must be visible
    # via ListHubContents, not just echoed back in CreateHubContentReference's own response.
    # A reference into a public Model is catalogued under the "ModelReference" content
    # type, distinct from the "Model" type used by the public hub's own original content.
    contents = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference")["HubContentSummaries"]
    found_names = [c["HubContentName"] for c in contents]
    assert content_name in found_names, f"expected {content_name!r} among {found_names!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_hub_in_service(sm, hub_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_hub(HubName=hub_name)["HubStatus"]
        if status == "InService":
            return
        if status == "CreateFailed":
            raise AssertionError(f"hub {hub_name} entered CreateFailed while provisioning")
        time.sleep(3)
    raise AssertionError(f"hub {hub_name} never reached InService, last status={status}")


def _pick_public_model_content_arn(sm) -> str:
    resp = sm.list_hub_contents(HubName="SageMakerPublicHub", HubContentType="Model", MaxResults=1)
    summaries = resp["HubContentSummaries"]
    if not summaries:
        raise AssertionError("SageMakerPublicHub returned no Model content to reference")
    # CreateHubContentReference's SageMakerPublicHubContentArn parameter matches
    # ".../Model/<name>" with NO trailing version segment (the version is instead supplied
    # separately via MinVersion) -- ListHubContents' HubContentArn includes a "/<version>"
    # suffix that must be stripped off here.
    arn = summaries[0]["HubContentArn"]
    prefix, _, tail = arn.rpartition("/")
    if tail and tail[0].isdigit():
        arn = prefix
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
