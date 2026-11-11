"""get-document-content-without-kb-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-document-content-without-kb-access-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDocumentContent by a role without bedrock-agent-runtime permissions gets AccessDeniedException
    with the exact message, while a permitted caller gets ResourceNotFoundException for the same
    never-ingested document."""
    kb_id = "ABCDEFGHIJ"  # matches ^[0-9a-zA-Z]{10}$, never created
    data_source_id = "DATASRC01"  # matches ^[0-9a-zA-Z]+$, len<=10
    document_id = "sim2real-doc-1"

    allowed_client = ctx.client("bedrock-agent-runtime")
    denied_client, denied_arn = _create_locked_down_client(ctx)
    _, partition, _, _, account_id, _ = denied_arn.split(":", 5)
    kb_arn = f"arn:{partition}:bedrock:{ctx.region}:{account_id}:knowledge-base/{kb_id}"

    def denied_call():
        denied_client.get_document_content(
            knowledgeBaseId=kb_id, dataSourceId=data_source_id, documentId=document_id
        )

    denied_code, denied_message = _error(denied_call)
    assert denied_code == "AccessDeniedException", denied_code
    expected_denied = (
        f"User: {denied_arn} is not authorized to perform: bedrock:GetDocumentContent on "
        f"resource: {kb_arn} because no identity-based policy allows the "
        f"bedrock:GetDocumentContent action"
    )
    assert denied_message == expected_denied, (
        f"expected message {expected_denied!r}, got {denied_message!r}"
    )

    # positive control: the fully-permitted principal reaches the service and gets a
    # resource-not-found error instead of an access-denied error for the same request.
    def allowed_call():
        allowed_client.get_document_content(
            knowledgeBaseId=kb_id, dataSourceId=data_source_id, documentId=document_id
        )

    allowed_code, allowed_message = _error(allowed_call)
    assert allowed_code == "ResourceNotFoundException", allowed_code
    expected_allowed = f"Knowledge Base with id {kb_id} does not exist"
    assert allowed_message == expected_allowed, (
        f"expected message {expected_allowed!r}, got {allowed_message!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_locked_down_client(ctx):
    """Create an IAM role with NO attached policies (implicit deny on everything),
    assume it, and return (bedrock-agent-runtime client under those credentials,
    assumed-role ARN)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-lockdown-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # IAM role trust policies are eventually consistent (documented propagation
    # window of a few to ~10s); poll assume_role rather than sleeping a fixed time.
    deadline = time.monotonic() + 30.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-lockdown")
            creds = assumed["Credentials"]
            assumed_arn = assumed["AssumedRoleUser"]["Arn"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume locked-down role in time: {last_exc}")

    # ctx.client(..., creds=...) re-signs with the assumed-role credentials while keeping
    # THIS run's endpoint (real AWS or emulator) and TLS settings.
    client = ctx.client(
        "bedrock-agent-runtime",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
