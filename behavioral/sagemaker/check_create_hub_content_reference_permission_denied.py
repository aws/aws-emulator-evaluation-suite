"""create-hub-content-reference-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-hub-content-reference-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHubContentReference called by a principal with no sagemaker permissions is
    denied with AccessDeniedException and creates no reference, while the same call made
    by the normal (permitted) principal succeeds."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    public_hub_contents = sm.list_hub_contents(
        HubName="SageMakerPublicHub", HubContentType="Model", MaxResults=20
    ).get("HubContentSummaries", [])
    if not public_hub_contents:
        raise AssertionError(
            "the SageMaker JumpStart public hub returned no Model content to reference "
            "in this region; cannot exercise CreateHubContentReference without a real "
            "SageMakerPublicHubContentArn."
        )

    hub_name = ctx.unique_name("sim2real-sm-hub-")
    sm.create_hub(
        HubName=hub_name,
        HubDescription="sim2real permission-denied test hub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_hub(HubName=hub_name))
    _wait_hub_in_service(sm, hub_name, timeout_s=120)

    # Find one public hub content item that this (fully-permitted) principal can
    # actually reference — some JumpStart listings require extra preconditions (e.g. EULA
    # acceptance) unrelated to IAM permissions, which also surface as ValidationException;
    # probing avoids conflating that with the AccessDenied behavior under test.
    #
    # ListHubContents' own HubContentArn is the source of truth for the ARN
    # CreateHubContentReference expects — it carries a trailing "/{version}" segment that
    # SageMakerPublicHubContentArn's pattern does not, so it must be stripped. A
    # reference is catalogued locally under the "ModelReference" content type, distinct
    # from the "Model" type used by the public hub's own original content.
    public_content_arn = None
    content_name = None
    for candidate in public_hub_contents:
        real_content_arn = candidate.get("HubContentArn")
        if not real_content_arn:
            continue
        candidate_arn = real_content_arn.rsplit("/", 1)[0]
        try:
            sm.create_hub_content_reference(
                HubName=hub_name, SageMakerPublicHubContentArn=candidate_arn
            )
        except ClientError:
            continue
        sm.delete_hub_content_reference(
            HubName=hub_name,
            HubContentType="ModelReference",
            HubContentName=candidate["HubContentName"],
        )
        _wait_no_hub_contents(sm, hub_name, timeout_s=120)
        public_content_arn = candidate_arn
        content_name = candidate["HubContentName"]
        break
    if public_content_arn is None:
        raise AssertionError(
            f"none of the first {len(public_hub_contents)} public hub Model contents could "
            f"be referenced by the fully-permitted principal (e.g. all require extra "
            f"preconditions like EULA acceptance); cannot isolate the AccessDenied behavior "
            f"under test from those unrelated rejections."
        )

    # -- negative: a principal with zero attached IAM permissions

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-sm-noperm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    limited_role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Trust-policy propagation, unrelated to the permission gap under test: bound the wait
    # to a deadline and retry AssumeRole rather than sleeping a fixed guess.
    deadline = time.monotonic() + 60
    creds = None
    last_exc = None
    session_name = ctx.unique_name("sim2real-sm-noperm-sess-")
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=limited_role_arn,
                RoleSessionName=session_name,
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume no-permission role in time: {last_exc}")

    # ctx.client keeps THIS target's endpoint/TLS/retry wiring while signing with the
    # permission-less identity; a bare boto3.client would lose that wiring and risk
    # answering the AccessDeniedException assertion from real AWS even when the target
    # under test is an emulator.
    limited_sm = ctx.client(
        "sagemaker",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _error_code_and_message(
        lambda: limited_sm.create_hub_content_reference(
            HubName=hub_name, SageMakerPublicHubContentArn=public_content_arn
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code} ({message!r})"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: sagemaker:CreateHubContentReference on resource: "
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:hub-content/{hub_name}/ModelReference/"
        f"{content_name} because no identity-based policy allows the "
        f"sagemaker:CreateHubContentReference action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no hub content reference was created by the denied call
    contents = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference").get(
        "HubContentSummaries", []
    )
    assert contents == [], f"denied call still created hub content: {contents}"

    # -- positive control: the same operation, same hub, with the normal principal succeeds
    resp = sm.create_hub_content_reference(
        HubName=hub_name, SageMakerPublicHubContentArn=public_content_arn
    )
    assert resp["HubArn"].endswith(f"hub/{hub_name}")

    def _delete_reference_and_wait():

        try:
            sm.delete_hub_content_reference(
                HubName=hub_name, HubContentType="ModelReference", HubContentName=content_name
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
            return
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            remaining = sm.list_hub_contents(
                HubName=hub_name, HubContentType="ModelReference"
            ).get("HubContentSummaries", [])
            if not remaining:
                return
            time.sleep(5)

    ctx.on_cleanup(_delete_reference_and_wait)

    contents_after = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference").get(
        "HubContentSummaries", []
    )
    assert len(contents_after) == 1


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS denies is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _wait_hub_in_service(sm, hub_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_hub(HubName=hub_name)["HubStatus"]
        if status == "InService":
            return
        if status in ("CreateFailed",):
            raise AssertionError(f"hub creation failed: {status}")
        time.sleep(5)
    raise AssertionError(f"hub never reached InService, last={status}")


def _wait_no_hub_contents(sm, hub_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = sm.list_hub_contents(HubName=hub_name, HubContentType="ModelReference").get(
            "HubContentSummaries", []
        )
        if not remaining:
            return
        time.sleep(5)
    raise AssertionError(f"hub content reference probe never fully deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
