"""cmk-trust-removed-then-restored-execution-redrive-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-trust-removed-then-restored-execution-redrive-succeeds"
GROUP = "cmk_encryption"
SERVICES = ["kms", "stepfunctions"]

_GOOD_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_BROKEN_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CMK-encrypted STANDARD execution started while its role's trust is removed fails
    States.Runtime "not authorized to assume the provided role"; restoring the trust and
    calling RedriveExecution on that same execution then resumes it to SUCCEEDED.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    iam = ctx.client("iam")

    key = kms.create_key(
        Description="sim2real-behav-sfn-cmk-trust-redrive",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    role_name = ctx.unique_name("sim2real-sfn-cmktrust-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_GOOD_TRUST,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="kms",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": key_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kms"))

    # Fresh key and role policies take seconds to propagate; retry setup-only errors.
    def _setup_retry(fn, timeout_s=90.0, interval_s=3.0):
        deadline = time.monotonic() + timeout_s
        last_exc = None
        while time.monotonic() < deadline:
            try:
                return fn()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code not in ("AccessDeniedException", "KmsAccessDeniedException"):
                    raise
                last_exc = exc
                time.sleep(interval_s)
        raise last_exc

    sm_name = ctx.unique_name("sim2real-sfn-cmktrustsm-")
    sm_arn = _setup_retry(
        lambda: sfn.create_state_machine(
            name=sm_name,
            definition=_DEFINITION,
            roleArn=role_arn,
            encryptionConfiguration={
                "type": "CUSTOMER_MANAGED_KMS_KEY",
                "kmsKeyId": key_id,
                "kmsDataKeyReusePeriodSeconds": 300,
            },
            tags=[{"key": "sim2real", "value": "true"}],
        )
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # Positive control: the role's trust is intact -> a baseline execution succeeds, proving
    # the CMK, role and state machine are wired correctly before the trust is broken.
    baseline_arn = _setup_retry(
        lambda: sfn.start_execution(stateMachineArn=sm_arn, input="{}")
    )["executionArn"]
    baseline_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=baseline_arn),
        lambda d: d["status"] != "RUNNING",
        description="baseline execution to reach a terminal state",
    )
    assert baseline_final["status"] == "SUCCEEDED", (
        f"baseline execution must SUCCEED before the trust is touched; got {baseline_final['status']!r} "
        f"cause={baseline_final.get('cause')!r}"
    )

    # Break the trust: the role no longer lets states.amazonaws.com assume it.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=_BROKEN_TRUST)

    def _start_broken():
        return sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]

    def _broken_final(exec_arn):
        return _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] != "RUNNING",
            description="trust-broken execution to reach a terminal state",
        )

    # StartExecution itself may still succeed (the failure surfaces inside the execution); retry
    # the whole start+poll pair until the FAILED/States.Runtime shape actually appears, since the
    # trust write needs to propagate first.
    deadline = time.monotonic() + 90
    broken_final = None
    broken_exec_arn = None
    while time.monotonic() < deadline:
        broken_exec_arn = _start_broken()
        broken_final = _broken_final(broken_exec_arn)
        if broken_final["status"] == "FAILED" and broken_final.get("error") == "States.Runtime":
            break
        time.sleep(3)
    assert broken_final["status"] == "FAILED", (
        f"expected FAILED once the trust is broken, got {broken_final['status']!r} "
        f"cause={broken_final.get('cause')!r}"
    )
    assert broken_final.get("error") == "States.Runtime", (
        f"expected error States.Runtime, got {broken_final.get('error')!r}"
    )
    expected_cause = (
        "com.amazonaws.sfn.invoker.sts.AssumeRoleFailedCacheableException: The principal "
        f"states.amazonaws.com is not authorized to assume the provided role. (role: {role_arn})"
    )
    assert broken_final.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {broken_final.get('cause')!r}"
    )
    assert broken_final["redriveStatus"] == "REDRIVABLE", (
        f"expected a FAILED top-level States.Runtime execution to be REDRIVABLE, got "
        f"{broken_final['redriveStatus']!r} ({broken_final.get('redriveStatusReason')!r})"
    )

    # Fix the trust, then RedriveExecution on the SAME failed execution. The assume-role failure
    # is itself cached for a short time (the SDK's own exception names it "Cacheable"), so the
    # first redrive after the fix can still see the stale denial; retry the redrive itself until
    # it actually clears, the same bounded way a fresh permission is retried at first use.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=_GOOD_TRUST)

    redriven_final = None
    redrive_attempts = 0
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            sfn.redrive_execution(executionArn=broken_exec_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3)
            continue
        redrive_attempts += 1
        redriven_final = _poll_until(
            lambda: sfn.describe_execution(executionArn=broken_exec_arn),
            lambda d: d["status"] != "RUNNING",
            description="redriven execution to reach a terminal state",
        )
        if redriven_final["status"] == "SUCCEEDED":
            break
        if redriven_final["redriveStatus"] != "REDRIVABLE":
            break
        time.sleep(3)
    assert redriven_final is not None and redriven_final["status"] == "SUCCEEDED", (
        f"expected the redriven execution to SUCCEED, got "
        f"{redriven_final['status'] if redriven_final else None!r} "
        f"error={redriven_final.get('error') if redriven_final else None!r} "
        f"cause={redriven_final.get('cause') if redriven_final else None!r}"
    )
    assert redriven_final["redriveCount"] == redrive_attempts, (
        f"expected redriveCount {redrive_attempts} after {redrive_attempts} RedriveExecution call(s), "
        f"got {redriven_final['redriveCount']!r}"
    )

    history_types = [e["type"] for e in sfn.get_execution_history(executionArn=broken_exec_arn)["events"]]
    assert "ExecutionRedriven" in history_types, (
        f"expected an ExecutionRedriven history event, got {history_types!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
