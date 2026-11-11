"""get-memory-record-cross-tenant-read-denied."""
from __future__ import annotations

import json
import random
import secrets
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-memory-record-cross-tenant-read-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A principal granted GetMemoryRecord on one memory resource is refused with
    AccessDeniedException on another memory's record, while on its own memory it reaches the lookup
    (ResourceNotFoundException, 'MemoryItem does not exist'): the grant is enforced per memory.
    """
    account_id = _account_id(ctx)
    owned_memory_id = f"tenanta-{_rand_suffix(10)}"
    other_memory_id = f"tenantb-{_rand_suffix(10)}"
    record_id = f"mem-{secrets.token_hex(20)}"
    owned_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:memory/{owned_memory_id}"

    restricted, role_name = _assume_role_client(
        ctx,
        "bedrock-agentcore",
        [{"Effect": "Allow", "Action": "bedrock-agentcore:GetMemoryRecord", "Resource": owned_arn}],
    )

    code, message = _error_retry(
        lambda: restricted.get_memory_record(
            memoryId=other_memory_id, memoryRecordId=record_id
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    other_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:memory/{other_memory_id}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-session "
        f"is not authorized to perform: bedrock-agentcore:GetMemoryRecord on resource: {other_arn} "
        "because no identity-based policy allows the bedrock-agentcore:GetMemoryRecord action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    control_code, control_message = _error_retry(
        lambda: restricted.get_memory_record(memoryId=owned_memory_id, memoryRecordId=record_id)
    )
    assert control_code == "ResourceNotFoundException", (
        "positive control: reading a record under the principal's own permitted (but "
        f"nonexistent) memory resource should reach resource-lookup logic, got {control_code}"
    )
    assert control_message == "MemoryItem does not exist", (
        f"expected message 'MemoryItem does not exist', got {control_message!r}"
    )


def _rand_suffix(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _error_retry(fn, *, transient=("UnrecognizedClientException",), attempts=5, delay=3.0):
    """Like _error, but retries when the observed error is a transient
    credential-propagation symptom (freshly-assumed STS sessions occasionally see
    UnrecognizedClientException on the first call to a new service endpoint) rather than
    the actual authorization decision under test."""
    last = None
    for _ in range(attempts):
        last = _error(fn)
        if last[0] not in transient:
            return last
        time.sleep(delay)
    return last


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_client(ctx, service: str, statements: list[dict[str, Any]]):
    """Create an IAM role whose inline policy is exactly `statements`, assume it, and return a
    client for `service` backed by the resulting temporary credentials, with the role's name."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = _account_id(ctx)
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "inline-scope"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    deadline = time.monotonic() + 30.0
    creds = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-session"
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(1.5)
    if creds is None:
        raise AssertionError(f"role never became assumable: {last_err}")

    # Signed through ctx.client(creds=...) so the second hop keeps this target's endpoint.
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
