"""payment-session-expiry-minutes-range-enforced-and-echoed."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "payment-session-expiry-minutes-range-enforced-and-echoed"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agentcore"]

# expiryTimeInMinutes must be between 15 and 480.
_MIN_EXPIRY_MIN = 15
_MAX_EXPIRY_MIN = 480
# Client/server clock skew plus request latency around createdAt.
_SKEW_S = 120


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePaymentSession refuses expiryTimeInMinutes 14 and 481 with ValidationException, and a
    session created with the 15-minute minimum echoes expiryTimeInMinutes=15 in Create and
    GetPaymentSession with a createdAt of now (within 120 s).

    Reference: https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_CreatePaymentSession.html
    """
    iam = ctx.client("iam")
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")
    raw = ctx.client("bedrock-agentcore", config=Config(parameter_validation=False))

    role_name = ctx.unique_name("sim2real-agentcore-pay-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    # CreatePaymentManager assumes this role to provision the workload identity backing the
    # payment manager's credential provider; without this grant the call is rejected with
    # ValidationException("...missing the required permission: bedrock-agentcore:CreateWorkloadIdentity").
    policy_name = "sim2real-payments-inline-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    manager_name = ("simrealpm" + uuid.uuid4().hex)[:40]
    pm = _create_payment_manager_with_retry(control, manager_name, role_arn)
    manager_id = pm["paymentManagerId"]
    manager_arn = pm["paymentManagerArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: control.delete_payment_manager(paymentManagerId=manager_id))
    )

    if not _poll_status(
        lambda: control.get_payment_manager(paymentManagerId=manager_id), "READY", 60
    ):
        raise AssertionError("PaymentManager never reached READY within 60s")

    user_id = ctx.unique_name("sim2real-pay-user-")

    for value, bound in ((_MIN_EXPIRY_MIN - 1, "greater than or equal to 15"),
                         (_MAX_EXPIRY_MIN + 1, "less than or equal to 480")):
        code, message = _error(
            lambda value=value: raw.create_payment_session(
                paymentManagerArn=manager_arn, expiryTimeInMinutes=value, userId=user_id
            )
        )
        assert code == "ValidationException", (
            f"expiryTimeInMinutes={value}: expected ValidationException, got {code}: {message!r}"
        )
        expected = (
            "1 validation error detected: Value at 'expiryTimeInMinutes' failed to satisfy "
            f"constraint: Member must have value {bound}"
        )
        assert message == expected, (
            f"expiryTimeInMinutes={value}: expected message {expected!r}, got {message!r}"
        )

    issued_at = datetime.now(timezone.utc)
    session = agentcore.create_payment_session(
        paymentManagerArn=manager_arn, expiryTimeInMinutes=_MIN_EXPIRY_MIN, userId=user_id
    )["paymentSession"]
    payment_session_id = session["paymentSessionId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: agentcore.delete_payment_session(
                paymentManagerArn=manager_arn,
                paymentSessionId=payment_session_id,
                userId=user_id,
            )
        )
    )
    assert session["expiryTimeInMinutes"] == _MIN_EXPIRY_MIN, (
        f"CreatePaymentSession must echo expiryTimeInMinutes={_MIN_EXPIRY_MIN}, got "
        f"{session['expiryTimeInMinutes']!r}"
    )
    created_offset_s = (session["createdAt"] - issued_at).total_seconds()
    assert -_SKEW_S <= created_offset_s <= _SKEW_S, (
        f"createdAt {session['createdAt']!r} is {created_offset_s:.0f}s from the request, "
        f"expected within {_SKEW_S}s"
    )

    got = agentcore.get_payment_session(
        paymentManagerArn=manager_arn, paymentSessionId=payment_session_id, userId=user_id
    )["paymentSession"]
    assert got["paymentSessionId"] == payment_session_id, (
        f"GetPaymentSession returned session {got.get('paymentSessionId')!r}, expected {payment_session_id!r}"
    )
    assert got["expiryTimeInMinutes"] == _MIN_EXPIRY_MIN, (
        f"GetPaymentSession must report expiryTimeInMinutes={_MIN_EXPIRY_MIN}, got "
        f"{got['expiryTimeInMinutes']!r}"
    )


def _error(fn):
    """Call fn(); return the refusal's (code, message). A success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _create_payment_manager_with_retry(control, manager_name: str, role_arn: str):
    # A freshly created IAM role's trust policy can take a few seconds to propagate before
    # bedrock-agentcore-control can assume it; retry on that specific transient rejection
    # window only, never on an unrelated or terminal error.
    deadline = time.monotonic() + 30.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return control.create_payment_manager(
                name=manager_name,
                authorizerType="AWS_IAM",
                roleArn=role_arn,
                tags={"sim2real": CHECK},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = e
                time.sleep(2.0)
                continue
            raise AssertionError(
                f"could not create a prerequisite PaymentManager ({code}: "
                f"{e.response['Error'].get('Message', '')}); account is likely not enrolled "
                "for AgentCore Payments"
            ) from e
    msg = last_err.response["Error"] if last_err else {"Code": "unknown", "Message": ""}
    raise AssertionError(
        f"CreatePaymentManager kept failing after the IAM role propagation window "
        f"({msg['Code']}: {msg.get('Message', '')}); account is likely not enrolled "
        "for AgentCore Payments"
    ) from last_err


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_status(probe, wanted: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = probe()
        if resp.get("status") == wanted:
            return True
        if resp.get("status", "").endswith("FAILED"):
            return False
        time.sleep(5)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
