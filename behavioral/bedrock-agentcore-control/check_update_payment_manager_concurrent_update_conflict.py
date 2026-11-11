"""update-payment-manager-concurrent-update-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-payment-manager-concurrent-update-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdatePaymentManager calls: any refusal is ConflictException with the exact message naming the
    account, manager id and version 1, and the manager settles READY with description "edit-a" or "edit-b"."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    pm = _create_payment_manager_with_role_retry(
        bac, _alnum_name(ctx, "sim2realpm"), role_arn, resource_tags={"sim2real:managed": "true"}
    )
    payment_manager_id = pm["paymentManagerId"]
    ctx.on_cleanup(lambda: bac.delete_payment_manager(paymentManagerId=payment_manager_id))
    _poll_until(
        lambda: bac.get_payment_manager(paymentManagerId=payment_manager_id),
        lambda r: r["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=60,
    )
    created = bac.get_payment_manager(paymentManagerId=payment_manager_id)
    assert created["status"] == "READY", f"expected payment manager READY after create, got {created}"

    def _updater(desc):
        return lambda: bac.update_payment_manager(paymentManagerId=payment_manager_id, description=desc)

    results = _race([_updater("edit-a"), _updater("edit-b")])
    [(i, r) for i, r in enumerate(results) if r[0]]
    failures = [r for r in results if not r[0]]
    # Any rejected writer must fail with ConflictException specifically (never a lost/merged
    # update); it is also valid for AWS to accept both concurrent writers and serialize
    # them internally.
    for _, (code, message) in failures:
        assert code == "ConflictException", f"expected losers to fail with ConflictException, got {code}"
        # Both writers race against the manager's first version, the one CreatePaymentManager made.
        expected_message = (
            "Conflict while updating payment manager: "
            f"accountId={ctx.account}, managerId={payment_manager_id}, version=1"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    final = _poll_until(
        lambda: bac.get_payment_manager(paymentManagerId=payment_manager_id),
        lambda r: r["status"] == "READY",
        timeout_s=60,
    )
    assert final.get("description") in ("edit-a", "edit-b"), (
        f"payment manager left in inconsistent state: {final}"
    )


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _create_agentcore_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bac-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreatePaymentManager requires the passed execution role to itself carry
    # bedrock-agentcore:CreateWorkloadIdentity (the service uses it to provision the
    # payment manager's backing workload identity) and, when the request also carries
    # tags, bedrock-agentcore:TagResource: an untagged create succeeds without it,
    # but a tagged one is rejected synchronously with ValidationException.
    permissions = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:CreateWorkloadIdentity",
                    "bedrock-agentcore:GetWorkloadIdentity",
                    "bedrock-agentcore:TagResource",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="agentcore-payments-inline", PolicyDocument=json.dumps(permissions)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="agentcore-payments-inline"))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


def _create_payment_manager_with_role_retry(
    bac, name, role_arn, timeout_s=120.0, interval_s=5.0, resource_tags=None
):
    """CreatePaymentManager validates the execution role's permissions synchronously; a
    role/policy created moments ago can still fail that check while IAM propagates it."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.create_payment_manager(
                name=name, authorizerType="AWS_IAM", roleArn=role_arn, tags=resource_tags or {}
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "missing the required permission" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            error = exc.response["Error"]
            return i, False, (error.get("Code"), error.get("Message"))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

