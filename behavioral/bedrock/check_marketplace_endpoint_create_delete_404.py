"""marketplace-endpoint-create-delete-404."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "marketplace-endpoint-create-delete-404"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMarketplaceModelEndpoint on a SageMaker public hub model the caller is not subscribed to
    returns ValidationException 'Caller is not subscribed to the marketplace offering.', and
    ListMarketplaceModelEndpoints for that offering is empty before and after.
    """
    bedrock = ctx.client("bedrock")
    sagemaker = ctx.client("sagemaker")

    hub_content_arn, instance_type = _discover_public_hub_model(sagemaker)
    role_arn = _create_sagemaker_execution_role(ctx)

    # Positive control: the Marketplace-endpoint control plane is reachable and this
    # account is otherwise authorized to call it, filtered to this offering -- so a
    # refusal below reads as "not subscribed to THIS offering", not "no permissions at
    # all" or "the client never reached the service".
    before = bedrock.list_marketplace_model_endpoints(modelSourceEquals=hub_content_arn)[
        "marketplaceModelEndpoints"
    ]
    assert before == [], (
        f"expected no pre-existing endpoint for {hub_content_arn!r}, found {before!r}"
    )

    endpoint_name = ctx.unique_name("sim2real-mktep-")[:30]

    def _create():
        return bedrock.create_marketplace_model_endpoint(
            modelSourceIdentifier=hub_content_arn,
            endpointConfig={
                "sageMaker": {
                    "initialInstanceCount": 1,
                    "instanceType": instance_type,
                    "executionRole": role_arn,
                }
            },
            endpointName=endpoint_name,
            acceptEula=True,
            tags=[{"key": "sim2real", "value": CHECK}],
        )

    try:
        # Only IAM role propagation is worth retrying on -- the subscription gate below
        # is a permanent per-account state, not a transient one, so retrying it would just
        # burn the retry budget waiting out a refusal that will not change mid-run.
        create_resp = _retry_transient(_create, retry_codes=("AccessDeniedException",))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
    else:
        # Unexpected: the offering accepted the create. Clean up what was created and fail.
        endpoint_arn = create_resp["marketplaceModelEndpoint"]["endpointArn"]

        def _cleanup():
            try:
                bedrock.delete_marketplace_model_endpoint(endpointArn=endpoint_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

        ctx.on_cleanup(_cleanup)
        raise AssertionError(
            f"expected CreateMarketplaceModelEndpoint on an unsubscribed offering "
            f"({hub_content_arn}) to be refused; it created {endpoint_arn!r} instead"
        )

    assert code == "ValidationException", (
        f"expected the unsubscribed-offering refusal to be ValidationException, got "
        f"{code!r}: {message!r}"
    )
    expected_message = "Caller is not subscribed to the marketplace offering."
    assert message == expected_message, (
        f"expected the subscription refusal message {expected_message!r}, got {message!r}"
    )

    after = bedrock.list_marketplace_model_endpoints(modelSourceEquals=hub_content_arn)[
        "marketplaceModelEndpoints"
    ]
    assert after == [], (
        f"expected the refused create to leave no endpoint for {hub_content_arn!r} in "
        f"ListMarketplaceModelEndpoints, found {after!r}"
    )


def _retry_transient(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "ValidationException")):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _discover_public_hub_model(sagemaker):
    resp = sagemaker.list_hub_contents(
        HubName="SageMakerPublicHub", HubContentType="Model", MaxResults=20
    )
    summaries = resp.get("HubContentSummaries", [])
    if not summaries:
        raise AssertionError("SageMakerPublicHub returned no listable model content to deploy")
    for summary in summaries:
        try:
            detail = sagemaker.describe_hub_content(
                HubName="SageMakerPublicHub",
                HubContentType="Model",
                HubContentName=summary["HubContentName"],
                HubContentVersion=summary["HubContentVersion"],
            )
        except Exception:
            continue
        doc = json.loads(detail.get("HubContentDocument", "{}"))
        instance_type = doc.get("DefaultDeploymentConfig", {}).get(
            "InstanceType"
        ) or doc.get("SupportedInferenceInstanceTypes", [None])[0]
        if instance_type:
            return detail["HubContentArn"], instance_type
    raise AssertionError(
        "no public hub model exposed a deployable default instance type to build the "
        "marketplace endpoint config from"
    )


def _create_sagemaker_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-exec-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )

    def _cleanup():
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
