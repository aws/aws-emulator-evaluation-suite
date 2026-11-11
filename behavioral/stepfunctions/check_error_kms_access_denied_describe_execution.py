"""error-kms-access-denied-describe-execution."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "error-kms-access-denied-describe-execution"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]
_SESSION_NAME = "sim2real-behav-kms-check"


# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeExecution on a CMK-encrypted execution needs the caller's own KMS decrypt access: a
    caller succeeds while granted on the key, gets KmsAccessDeniedException once the grant is
    removed, and succeeds again once it is restored.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    caller_identity = sts.get_caller_identity()
    account_id = caller_identity["Account"]

    # StartExecution and CreateStateMachine on a CMK-encrypted machine need the *caller* to hold
    # kms:Decrypt/kms:GenerateDataKey on the key; an assumed-role session gets no implicit grant
    # on a fresh CMK, so the underlying role is granted access in the key policy.
    caller_arn = caller_identity["Arn"]
    if ":assumed-role/" in caller_arn:
        harness_role_name = caller_arn.split(":assumed-role/")[1].split("/")[0]
        harness_principal_arn = f"arn:aws:iam::{account_id}:role/{harness_role_name}"
    else:
        harness_principal_arn = caller_arn

    # Created before the CMK so its ARN can be granted from the start; toggling that one
    # statement distinguishes key-policy enforcement from denying every non-owning caller.
    caller_role_name = ctx.unique_name("sim2real-sfn-caller-")
    caller_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": account_id}, "Action": "sts:AssumeRole"}],
    }
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps(caller_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=caller_role_name))
    caller_policy_name = ctx.unique_name("sim2real-sfn-caller-policy-")
    iam.put_role_policy(
        RoleName=caller_role_name,
        PolicyName=caller_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName=caller_policy_name))

    # No kms:ViaService condition below: "states.<region>.amazonaws.com" is not a documented
    # kms:ViaService endpoint, so a grant conditioned on it never applies and AWS permanently
    # denies calls made under it. Every principal below gets unconditional access instead.
    base_statements = [
        {
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
        {
            "Sid": "AllowHarnessCallerForSetup",
            "Effect": "Allow",
            "Principal": {"AWS": harness_principal_arn},
            "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
            "Resource": "*",
        },
    ]
    restricted_caller_statement = {
        "Sid": "AllowRestrictedCaller",
        "Effect": "Allow",
        "Principal": {"AWS": caller_role_arn},
        "Action": ["kms:Decrypt", "kms:DescribeKey"],
        "Resource": "*",
    }
    granted_key_policy = {"Version": "2012-10-17", "Statement": base_statements + [restricted_caller_statement]}
    revoked_key_policy = {"Version": "2012-10-17", "Statement": list(base_statements)}

    # The key policy above names caller_role_arn, a role created moments ago -- KMS validates
    # every policy principal against IAM at write time and real AWS returns
    # MalformedPolicyDocumentException ("invalid principals") until that role has propagated to
    # where KMS's own validator can see it. Retry only that specific, expected-to-clear error.
    key = _call_with_setup_retry(
        lambda: kms.create_key(
            Description="sim2real-behav-sfn-sm-cmk",
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Policy=json.dumps(granted_key_policy),
            Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
        )
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # The state machine's OWN execution role must also be able to use the CMK (via the states
    # service) to decrypt/generate data keys for caching assumed-role credentials, or
    # StartExecution itself fails with KmsAccessDeniedException before we ever get to the
    # caller-side check this test is actually about.
    sm_role_arn = _create_sfn_role(
        ctx,
        inline_statements=[
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": key_arn,
            }
        ],
    )

    sm_name = ctx.unique_name("sim2real-behav-sm-cmk-")
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    # Fresh key and role policies take seconds to propagate, so setup calls can transiently see
    # KmsAccessDeniedException or AccessDeniedException; retry them until both take effect.
    sm_arn = _call_with_setup_retry(
        lambda: sfn.create_state_machine(
            name=sm_name,
            definition=definition,
            roleArn=sm_role_arn,
            encryptionConfiguration={
                "type": "CUSTOMER_MANAGED_KMS_KEY",
                "kmsKeyId": key_id,
                "kmsDataKeyReusePeriodSeconds": 300,
            },
            tags=[{"key": "sim2real:managed", "value": "true"}],
        )
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = _call_with_setup_retry(lambda: sfn.start_execution(stateMachineArn=sm_arn, input="{}"))["executionArn"]
    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=2.0,
        description="the CMK-encrypted execution leaves RUNNING",
    )

    creds = _assume_role_with_retry(sts, caller_role_arn)
    restricted_sfn = ctx.client(
        "stepfunctions",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Positive control: the caller holds the KMS grant, so its DescribeExecution succeeds.
    _poll_until(
        lambda: _succeeds(lambda: restricted_sfn.describe_execution(executionArn=exec_arn)),
        lambda ok: ok,
        timeout_s=120.0,
        interval_s=5.0,
        description="the KMS-granted caller role's DescribeExecution succeeds (positive control)",
    )

    # Drop only the caller's KMS grant; setup and execution-role grants stay so cleanup works.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(revoked_key_policy))

    # The specific error, once the policy write has propagated.
    code, message = _refusal_with_retry(lambda: restricted_sfn.describe_execution(executionArn=exec_arn))
    assert code == "KmsAccessDeniedException", f"expected KmsAccessDeniedException, got {code!r}"
    # AWS appends the inner KMS call's request id and SDK attempt count to the not-authorized text.
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no identity-based policy "
        "allows the kms:Decrypt action (Service: Kms, Status Code: 400, Request ID: <request-id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert _stable(message) == expected, f"expected message {expected!r}, got {message!r}"

    # Restore the grant; the identical call must succeed again.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(granted_key_policy))
    _poll_until(
        lambda: _succeeds(lambda: restricted_sfn.describe_execution(executionArn=exec_arn)),
        lambda ok: ok,
        timeout_s=120.0,
        interval_s=5.0,
        description="the caller role's DescribeExecution succeeds again once the KMS grant is restored",
    )


def _is_retryable_setup_error(exc):
    error = exc.response.get("Error", {})
    code = error.get("Code")
    if code in ("KmsAccessDeniedException", "AccessDeniedException"):
        # Setup calls (CreateStateMachine / StartExecution) made by the harness's own principal
        # can transiently see KmsAccessDeniedException while a freshly-written KMS key policy
        # propagates, or AccessDeniedException while the state-machine role's own freshly-written
        # trust/inline policy propagates.
        return True
    if code == "MalformedPolicyDocumentException" and "principal" in error.get("Message", "").lower():
        # CreateKey/PutKeyPolicy validate every policy principal against IAM at write time; a
        # role created moments ago is not yet visible to that validator and this is the specific
        # error real AWS returns until it is.
        return True
    return False


def _call_with_setup_retry(fn, timeout_s=60.0, interval_s=3.0):
    # Retry only the specific, expected-to-clear errors above; any other failure (including one
    # of them past the deadline) still propagates.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if not _is_retryable_setup_error(exc):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _succeeds(fn):
    """True when fn() returns, False when it raises a ClientError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        return False
    return True


def _refusal_with_retry(fn, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it is refused KmsAccessDeniedException; return that (code, message).

    The caller role's freshly written identity policy and the revoked key policy both take time
    to propagate, so a plain AccessDeniedException or a success may come first. Past the deadline
    the last refusal is returned, and a call that still succeeds raises.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == "KmsAccessDeniedException":
                return last
        else:
            last = None
            last_result = result
        time.sleep(interval_s)
    if last is None:
        raise AssertionError(f"expected the call to be refused, it still succeeds with {last_result!r}")
    return last


def _assume_role_with_retry(sts, role_arn, attempts=6, interval_s=3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except Exception as exc:  # role trust may not have propagated yet
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn!r} after retries: {last_exc}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
