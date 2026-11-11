"""payment-manager-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "payment-manager-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PaymentManager create->update(roleArn)->delete state machine; unusable post-delete."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn_1 = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3pm1")
    role_arn_2 = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3pm2")
    name = _payments_name(ctx, "sim2realpm")

    created = client.create_payment_manager(
        name=name,
        authorizerType="AWS_IAM",
        roleArn=role_arn_1,
    )
    manager_id = created["paymentManagerId"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, manager_id))
    assert created["roleArn"] == role_arn_1, (
        f"CreatePaymentManager echoed roleArn={created['roleArn']!r}, expected {role_arn_1!r}"
    )

    _poll_until(
        lambda: client.get_payment_manager(paymentManagerId=manager_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )

    client.update_payment_manager(paymentManagerId=manager_id, roleArn=role_arn_2)
    updated = _poll_until(
        lambda: client.get_payment_manager(paymentManagerId=manager_id),
        lambda r: r["status"] == "READY" and r["roleArn"] == role_arn_2,
        timeout_s=180.0,
    )
    assert updated["roleArn"] == role_arn_2, (
        f"GetPaymentManager reported roleArn={updated['roleArn']!r} after UpdatePaymentManager, "
        f"expected {role_arn_2!r}"
    )

    delete_resp = client.delete_payment_manager(paymentManagerId=manager_id)
    assert delete_resp["status"] == "DELETING", (
        f"DeletePaymentManager returned status={delete_resp['status']!r}, expected 'DELETING'"
    )

    final_code, final_message = _poll_gone(
        lambda: client.get_payment_manager(paymentManagerId=manager_id), timeout_s=180.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"GetPaymentManager on the deleted manager returned code={final_code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_final = f"Payment manager not found: {manager_id}"
    assert final_message == expected_final, f"expected message {expected_final!r}, got {final_message!r}"

    update_after_delete_code, update_after_delete_message = _error_detail(
        lambda: client.update_payment_manager(paymentManagerId=manager_id, roleArn=role_arn_1)
    )
    assert update_after_delete_code == "ResourceNotFoundException", (
        f"UpdatePaymentManager on the deleted manager returned code={update_after_delete_code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_update = f"Payment manager not found: {manager_id}"
    assert update_after_delete_message == expected_update, (
        f"expected message {expected_update!r}, got {update_after_delete_message!r}"
    )


def _payments_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    alnum = "".join(ch for ch in raw if ch.isalnum())
    return alnum[:48]


def _create_role(ctx, principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-payments-permissions",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_ignore(iam, role_name, "sim2real-payments-permissions"))
    return arn


def _delete_role_policy_ignore(iam, role_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=180.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _delete_ignore_not_found(client, manager_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_payment_manager(paymentManagerId=manager_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
