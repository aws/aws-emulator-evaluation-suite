"""payment-session-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "payment-session-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePaymentSession is retrievable via GetPaymentSession and DeletePaymentSession
    removes it, causing GetPaymentSession to return ResourceNotFoundException."""
    data = ctx.client("bedrock-agentcore")
    control = ctx.client("bedrock-agentcore-control")

    manager_arn = _create_payment_manager(ctx, control)
    user_id = ctx.unique_name("sim2real-payments-user-")

    created = data.create_payment_session(
        paymentManagerArn=manager_arn, expiryTimeInMinutes=15, userId=user_id
    )
    session = created["paymentSession"]
    session_id = session["paymentSessionId"]
    assert session["paymentManagerArn"] == manager_arn, (
        f"expected paymentManagerArn={manager_arn!r}, got {session['paymentManagerArn']!r}"
    )
    ctx.on_cleanup(lambda: _best_effort_delete(data, manager_arn, session_id, user_id))

    got = data.get_payment_session(
        paymentManagerArn=manager_arn, paymentSessionId=session_id, userId=user_id
    )
    assert got["paymentSession"]["paymentSessionId"] == session_id, (
        f"expected paymentSessionId={session_id!r}, got {got['paymentSession']['paymentSessionId']!r}"
    )
    assert got["paymentSession"]["userId"] == user_id, (
        f"expected userId={user_id!r}, got {got['paymentSession']['userId']!r}"
    )
    assert got["paymentSession"]["expiryTimeInMinutes"] == 15, (
        f"expected expiryTimeInMinutes=15, got {got['paymentSession']['expiryTimeInMinutes']!r}"
    )

    data.delete_payment_session(
        paymentManagerArn=manager_arn, paymentSessionId=session_id, userId=user_id
    )

    code, message = _error(
        lambda: data.get_payment_session(
            paymentManagerArn=manager_arn, paymentSessionId=session_id, userId=user_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected GetPaymentSession on a deleted session to fail with ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Payment session not found: {session_id}", (
        f"expected the exact not-found message for {session_id!r}, got {message!r}"
    )


def _create_payment_manager(ctx, control) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-agentcore-payments-")[:64]
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
    import json

    try:
        role = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
    except Exception as exc:
        raise AssertionError(f"could not create prerequisite IAM role: {exc!r}") from exc
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    # CreatePaymentManager requires the passed execution role to itself carry
    # bedrock-agentcore:CreateWorkloadIdentity (the service uses it to provision the
    # payment manager's backing workload identity).
    policy_name = "sim2real-agentcore-payments-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock-agentcore:CreateWorkloadIdentity",
                            "bedrock-agentcore:GetWorkloadIdentity",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    name = _sanitize(ctx.unique_name("sim2realpm"))
    resp = _create_payment_manager_with_role_retry(control, name, role_arn)
    manager_arn = resp["paymentManagerArn"]
    manager_id = resp["paymentManagerId"]

    def _cleanup():
        try:
            control.delete_payment_manager(paymentManagerId=manager_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 120.0
    status = resp.get("status")
    while status in ("CREATING", "PENDING") and time.monotonic() < deadline:
        time.sleep(3.0)
        described = control.get_payment_manager(paymentManagerId=manager_id)
        status = described.get("status")
    if not status or "FAILED" in status:
        raise AssertionError(f"PaymentManager entered status={status!r} instead of becoming ready")
    if status in ("CREATING", "PENDING"):
        raise AssertionError(f"PaymentManager did not leave status={status!r} within the deadline")
    return manager_arn


def _create_payment_manager_with_role_retry(control, name: str, role_arn: str, timeout_s: float = 120.0):
    """CreatePaymentManager validates the execution role's permissions synchronously; a
    role/policy created moments ago can still fail that check while IAM propagates it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return control.create_payment_manager(name=name, authorizerType="AWS_IAM", roleArn=role_arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "missing the required permission" in msg:
                last_exc = exc
                time.sleep(5.0)
                continue
            raise AssertionError(
                f"CreatePaymentManager failed: {exc!r}. AgentCore Payments may not be enabled "
                "for this account/region, or the trust policy on the service role was rejected."
            ) from exc
    raise AssertionError(
        f"CreatePaymentManager still rejecting the execution role's permissions after {timeout_s}s: {last_exc!r}"
    )


def _sanitize(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum())
    if not cleaned[:1].isalpha():
        cleaned = "p" + cleaned
    return cleaned[:48]


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete(data, manager_arn: str, session_id: str, user_id: str) -> None:
    try:
        data.delete_payment_session(
            paymentManagerArn=manager_arn, paymentSessionId=session_id, userId=user_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
