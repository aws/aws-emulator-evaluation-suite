"""deregister-webhook-validation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-webhook-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterWebhookWithThirdParty rejects a name violating [A-Za-z0-9.@-_]+ with
    ValidationException, an unregistered name with WebhookNotFoundException, and a
    non-GITHUB_HMAC webhook with ValidationException."""
    cp = ctx.client("codepipeline")
    role_arn = _cp_create_role(ctx)
    bucket = _cp_create_bucket(ctx)
    provider = _cp_create_custom_source_type(ctx)
    pipeline = _cp_create_pipeline(ctx, role_arn, bucket, provider)

    malformed_name = "bad name with spaces!"  # violates [A-Za-z0-9.@\-_]+
    code_validation, msg_validation = _error(lambda: cp.deregister_webhook_with_third_party(webhookName=malformed_name))
    assert code_validation == "ValidationException", f"malformed name: expected ValidationException, got {code_validation}"
    assert msg_validation == (
        "1 validation error detected: Value at 'webhookName' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: [A-Za-z0-9.@\-_]+"
    ), f"malformed name: unexpected message {msg_validation!r}"

    unknown_name = ctx.unique_name("sim2real-cp-nowebhook-")
    code_not_found, msg_not_found = _error(lambda: cp.deregister_webhook_with_third_party(webhookName=unknown_name))
    assert code_not_found == "WebhookNotFoundException", f"unknown name: expected WebhookNotFoundException, got {code_not_found}"
    assert msg_not_found == "", f"unknown name: unexpected message {msg_not_found!r}"

    existing_names = {w["definition"]["name"] for w in cp.list_webhooks().get("webhooks", [])}
    assert malformed_name not in existing_names, f"malformed name {malformed_name!r} should not appear in list_webhooks"
    assert unknown_name not in existing_names, f"unknown name {unknown_name!r} should not appear in list_webhooks"

    # Deregister only applies to webhooks using GITHUB_HMAC; an UNAUTHENTICATED one is refused.
    webhook_name = _cp_create_webhook(ctx, pipeline, "SourceAction")
    existing_names = {w["definition"]["name"] for w in cp.list_webhooks().get("webhooks", [])}
    assert webhook_name in existing_names, f"expected {webhook_name!r} in list_webhooks, got {existing_names}"
    code_wrong_auth, msg_wrong_auth = _error(lambda: cp.deregister_webhook_with_third_party(webhookName=webhook_name))
    assert code_wrong_auth == "ValidationException", f"wrong-auth webhook: expected ValidationException, got {code_wrong_auth}"
    assert msg_wrong_auth == (
        f"Webhook {webhook_name} must be configured with GITHUB_HMAC authentication type. Type is UNAUTHENTICATED."
    ), f"wrong-auth webhook: unexpected message {msg_wrong_auth!r}"




def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cp_create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cp-access"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _cp_create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _cp_create_custom_source_type(ctx) -> str:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("cpsrc-")[:25]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return provider


def _cp_create_pipeline(ctx, role_arn, bucket, provider, extra_stages=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        }
    ]
    if extra_stages:
        stages.extend(extra_stages)
    else:
        # CodePipeline requires a minimum of 2 stages.
        stages.append(
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            }
        )
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(
                pipeline={
                    "name": name,
                    "roleArn": role_arn,
                    "artifactStore": {"type": "S3", "location": bucket},
                    "stages": stages,
                }
            )
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _cp_create_webhook(ctx, pipeline_name, action_name) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-wh-")
    cp.put_webhook(
        webhook={
            "name": name,
            "targetPipeline": pipeline_name,
            "targetAction": action_name,
            "filters": [{"jsonPath": "$.ref", "matchEquals": "refs/heads/{Branch}"}],
            "authentication": "UNAUTHENTICATED",
            "authenticationConfiguration": {},
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_webhook(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
