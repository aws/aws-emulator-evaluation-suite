"""integration-error-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-error-semantics"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIntegration rejects a nonexistent SourceArn or TargetArn synchronously with
    InvalidParameterValue and its exact message, each isolated by keeping the other ARN real, and
    accepts two real ARNs."""
    redshift = ctx.client("redshift")
    redshift_serverless = ctx.client("redshift-serverless")
    dynamodb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    account_id = sts.get_caller_identity()["Account"]

    source_kms_key_id = _create_kms_key(ctx, kms)
    real_source_arn = _create_dynamodb_source(
        ctx, dynamodb, ctx.unique_name("sim2real-integ-src-"), ctx.region, account_id, source_kms_key_id
    )

    target_kms_key_id = _create_kms_key(ctx, kms)
    real_target_arn = _create_namespace(
        ctx, redshift_serverless, ctx.unique_name("sim2real-integ-ns-"), target_kms_key_id
    )

    bogus_source_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{account_id}:"
        f"table/{ctx.unique_name('sim2real-integ-nosrc-')}"
    )
    bogus_target_arn = (
        f"arn:aws:redshift-serverless:{ctx.region}:{account_id}:"
        "namespace/00000000-0000-0000-0000-000000000000"
    )

    # The target must authorize the inbound integration first, or CreateIntegration rejects for
    # lack of authorization before validating ARN existence.
    _authorize_integration_target(redshift, real_target_arn, account_id, [real_source_arn, bogus_source_arn])

    # Nonexistent source, real target. Policies and KMS grants propagate slowly, so transient
    # readiness errors are retried (bounded) before the outcome is asserted.
    code_a, message_a = _create_integration_and_get_fault(
        ctx, redshift, "sim2real-integ-a-", bogus_source_arn, real_target_arn
    )
    assert code_a == "InvalidParameterValue", (
        f"expected InvalidParameterValue for nonexistent source, got {code_a}"
    )
    assert message_a == (
        "You don't have access to zero-ETL integrations because the source DynamoDB table doesn't exist or "
        "you don't have the required permissions. Check the resource and key policy on the source table and "
        "make sure you have the required permissions. Refer to the Amazon DynamoDB Developer Guide for "
        "instructions on how to update the policy if required and then continue creating the integration."
    ), message_a

    # Real source, a namespace UUID that was never created.
    code_b, message_b = _create_integration_and_get_fault(
        ctx, redshift, "sim2real-integ-b-", real_source_arn, bogus_target_arn
    )
    assert code_b == "InvalidParameterValue", (
        f"expected InvalidParameterValue for nonexistent target, got {code_b}"
    )
    assert message_b == (
        "You don't have access to zero-ETL integrations because the Amazon Redshift data warehouse doesn't "
        "exist or you don't have the required permissions. Check the resource policy of the data warehouse "
        "and make sure your user or role is specified as an authorized principal."
    ), message_b

    # Positive control: two real ARNs must pass, or the InvalidParameterValue above could be an
    # unmet zero-ETL prerequisite rather than an ARN-existence check.
    _assert_create_integration_accepts(ctx, redshift, "sim2real-integ-ctrl-", real_source_arn, real_target_arn)


_TRANSIENT_AUTHZ_CODES = (
    "AccessDeniedException",
    "AccessDenied",
    "InvalidPolicyFault",
    "UnauthorizedOperation",
    "UnauthorizedException",
    "AuthorizationNotFoundFault",
    "InvalidAuthorizationStateFault",
    "ResourceNotFoundException",
    "ValidationException",
    "UnsupportedOperationFault",
    "InvalidClusterStateFault",
    # While policies propagate, a real, correctly configured target can briefly be reported as
    # not found.
    "IntegrationTargetNotFoundFault",
    # KMS key-policy changes are eventually consistent and can take minutes to apply.
    "KMSKeyNotAccessibleFault",
)


def _create_integration_and_get_fault(
    ctx, redshift, name_prefix: str, source_arn: str, target_arn: str,
    # The first integration against a freshly authorized target and KMS key can take well over
    # 10 minutes to settle out of "creating".
    timeout: float = 2700.0, interval: float = 15.0,
):
    """Create the integration and return its terminal fault (code, message), or (None, None) on success, retrying
    transient readiness codes with a fresh integration each attempt.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            resp = redshift.create_integration(
                IntegrationName=ctx.unique_name(name_prefix),
                SourceArn=source_arn,
                TargetArn=target_arn,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _TRANSIENT_AUTHZ_CODES and time.monotonic() < deadline:
                time.sleep(interval)
                continue
            return code, exc.response.get("Error", {}).get("Message")

        integration_arn = resp["IntegrationArn"]
        ctx.on_cleanup(lambda arn=integration_arn: _delete_integration(redshift, arn))

        status = resp.get("Status")
        errors = resp.get("Errors") or []
        while status not in ("failed", "active") and time.monotonic() < deadline:
            time.sleep(interval)
            described = redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"][0]
            status = described.get("Status")
            errors = described.get("Errors") or []

        code = errors[0].get("ErrorCode") if errors else None
        if code in _TRANSIENT_AUTHZ_CODES and time.monotonic() < deadline:
            # A failed attempt still occupies the target's integration slot, so a retry without
            # deleting it is rejected with IntegrationConflictOperationFault.
            _delete_integration_and_wait(redshift, integration_arn, deadline, interval)
            continue
        return code, errors[0].get("ErrorMessage") if errors else None


def _assert_create_integration_accepts(
    ctx, redshift, name_prefix: str, source_arn: str, target_arn: str,
    timeout: float = 220.0, interval: float = 10.0,
) -> None:
    """Assert the synchronous call accepts a real source/target pairing, without waiting for the
    integration to become active.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            resp = redshift.create_integration(
                IntegrationName=ctx.unique_name(name_prefix),
                SourceArn=source_arn,
                TargetArn=target_arn,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message") or ""
            transient = code in _TRANSIENT_AUTHZ_CODES or (
                code == "InvalidParameterValue" and "key policy on the source table" in message
            )
            if transient and time.monotonic() < deadline:
                time.sleep(interval)
                continue
            assert code != "InvalidParameterValue", (
                "positive control: CreateIntegration with two real, correctly-"
                "provisioned ARNs was rejected as InvalidParameterValue "
                f"(got {code!r}: {message!r}) -- the InvalidParameterValue asserted "
                "for the nonexistent-ARN cases above would be indistinguishable from "
                "a setup defect rather than an ARN-existence check"
            )
            return
        integration_arn = resp["IntegrationArn"]
        ctx.on_cleanup(lambda arn=integration_arn: _delete_integration(redshift, arn))
        assert resp.get("Status") in ("creating", "active"), (
            "positive control: expected CreateIntegration to accept two real ARNs, "
            f"got Status={resp.get('Status')!r}"
        )
        return


def _delete_integration_and_wait(redshift, integration_arn: str, deadline: float, interval: float) -> None:
    """Delete an integration and wait (bounded) for it to clear the target's slot."""
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError:
        pass
    while time.monotonic() < deadline:
        try:
            described = redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"][0]
        except ClientError:
            return
        if described.get("Status") not in ("deleting",):
            return
        time.sleep(interval)


def _delete_integration(redshift, integration_arn: str) -> None:
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "IntegrationNotFoundFault":
            raise


def _create_dynamodb_source(
    ctx, dynamodb, name: str, region: str, account_id: str, kms_key_id: str
) -> str:
    # Redshift must decrypt the source table, so it uses the customer-managed key whose policy
    # authorizes redshift.amazonaws.com.
    dynamodb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        SSESpecification={"Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": kms_key_id},
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=name))

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if dynamodb.describe_table(TableName=name)["Table"]["TableStatus"] == "ACTIVE":
            break
        time.sleep(3)

    table_arn = dynamodb.describe_table(TableName=name)["Table"]["TableArn"]

    # Zero-ETL requires PITR on the source. A just-ACTIVE table answers
    # ContinuousBackupsUnavailableException for a few seconds, so retry (bounded).
    pitr_deadline = time.monotonic() + 60
    while True:
        try:
            dynamodb.update_continuous_backups(
                TableName=name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            break
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") == "ContinuousBackupsUnavailableException"
                and time.monotonic() < pitr_deadline
            ):
                time.sleep(5)
                continue
            raise
    # Zero-ETL requires a source resource policy authorizing Redshift to read the table.
    dynamodb.put_resource_policy(
        ResourceArn=table_arn,
        Policy=json.dumps(_ddb_source_policy(account_id, region, name)),
    )
    return table_arn


def _ddb_source_policy(account_id: str, region: str, table_name: str) -> dict:
    integration_arn_pattern = f"arn:aws:redshift:{region}:{account_id}:integration:*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftDescribeAndExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["dynamodb:ExportTableToPointInTime", "dynamodb:DescribeTable"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": integration_arn_pattern},
                },
            },
            {
                "Sid": "AllowRedshiftDescribeExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "dynamodb:DescribeExport",
                "Resource": f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}/export/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": integration_arn_pattern},
                },
            },
        ],
    }


def _create_namespace(ctx, redshift_serverless, name: str, kms_key_id: str) -> str:
    # Zero-ETL requires the target namespace to use a customer-managed KMS key.
    resp = redshift_serverless.create_namespace(namespaceName=name, kmsKeyId=kms_key_id)
    namespace_arn = resp["namespace"]["namespaceArn"]
    ctx.on_cleanup(lambda: redshift_serverless.delete_namespace(namespaceName=name))

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = redshift_serverless.get_namespace(namespaceName=name)["namespace"]["status"]
        if status == "AVAILABLE":
            break
        time.sleep(3)
    return namespace_arn


def _authorize_integration_target(redshift, target_arn: str, account_id: str, source_arns: list[str]) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AuthorizeIntegrationFromSources",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": target_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": source_arns}},
            },
            {
                "Sid": "AllowCreateInboundIntegration",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": target_arn,
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=target_arn, Policy=json.dumps(policy))


def _create_kms_key(ctx, kms) -> str:
    resp = kms.create_key(Description="sim2real integration-error-semantics test key")
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # The default key policy does not grant redshift.amazonaws.com, which zero-ETL needs to use the
    # target namespace's key.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableIamUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowRedshiftServiceUseOfKey",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": [
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:CreateGrant",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext",
                ],
                "Resource": "*",
            },
        ],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    return key_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
