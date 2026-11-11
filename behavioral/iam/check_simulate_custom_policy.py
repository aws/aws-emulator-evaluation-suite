"""simulate-custom-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "simulate-custom-policy"
GROUP = 'policy_simulation'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _simple_policy_document(actions, resource="*", effect="Allow"):
    """A minimal single-statement identity policy document (JSON string)."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": actions, "Resource": resource}],
        }
    )


def _unprivileged_client(ctx):
    """A brand-new IAM user with ZERO attached permissions + a minted access key, returned as
    (IAM client authenticated as that user, the user's ARN). A fresh IAM principal implicit-denies
    everything, so any call through it is expected AccessDenied. Access-key propagation is not
    instant, so poll STS until the key is recognized, and raise if it never is. Cleanup is
    registered."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    user_arn = iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["User"]["Arn"]

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            if last_code not in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"access key for {user_name} never propagated to STS within {budget_s:.0f}s; "
                    f"last error {last_code!r}"
                )
            time.sleep(3)
    return ctx.client("iam", creds=creds), user_arn


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SimulateCustomPolicy evaluates an unattached policy: s3:ListBucket (allowed by it) is
    'allowed' and s3:DeleteBucket (not mentioned) is 'implicitDeny'; a zero-permission user
    calling the simulator is refused with AccessDenied and its exact message."""
    iam = ctx.client("iam")
    bucket_arn = f"arn:aws:s3:::{ctx.unique_name('bucket-simcustom-')}"
    policy_doc = _simple_policy_document(["s3:ListBucket"], resource=bucket_arn)

    result = iam.simulate_custom_policy(
        PolicyInputList=[policy_doc],
        ActionNames=["s3:ListBucket", "s3:DeleteBucket"],
        ResourceArns=[bucket_arn],
    )
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in result["EvaluationResults"]}
    assert decisions["s3:ListBucket"] == "allowed", decisions
    assert decisions["s3:DeleteBucket"] == "implicitDeny", decisions

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    code, msg = _error(
        lambda: unpriv.simulate_custom_policy(
            PolicyInputList=[policy_doc], ActionNames=["s3:ListBucket"]
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code}"
    want = (f"User: {unpriv_arn} is not authorized to perform: iam:SimulateCustomPolicy on "
            "resource: * because no identity-based policy allows the iam:SimulateCustomPolicy action")
    assert msg == want, f"AccessDenied message: wanted {want!r}, got {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
