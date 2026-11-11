"""least-privilege-delete-tape-pool-denied-then-allowed."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "least-privilege-delete-tape-pool-denied-then-allowed"
GROUP = "permission-boundaries"
SERVICES = ["iam", "storagegateway"]

_PROPAGATION_TIMEOUT_S = 90.0
_POLL_INTERVAL_S = 5.0
# IAM has not converged yet, NOT "the control blocked" -- only polled on the leg that expects
# success, where a denial is indistinguishable from an unpropagated grant.
_UNCONVERGED = frozenset(
    {
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "SignatureDoesNotMatch",
        "AccessDeniedException",
    }
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_user_and_keys(ctx, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            iam.delete_user_policy(UserName=user_name, PolicyName=name)
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _teardown_pool(ctx, pool_arn_box: dict) -> None:
    arn = pool_arn_box.get("arn")
    if arn is None:
        return
    try:
        ctx.client("storagegateway").delete_tape_pool(PoolARN=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGatewayRequestException":
            raise


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal granted only ListTapePools/CreateTapePool can create a tape pool but is denied
    DeleteTapePool on it with AccessDeniedException; the unrestricted principal then deletes the
    identical pool, proving the denial was the policy and not a broken resource.
    """
    iam = ctx.client("iam")
    sg = ctx.client("storagegateway")

    user_name = ctx.unique_name("sim2real-sgw-leastpriv-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_and_keys(ctx, user_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["storagegateway:ListTapePools", "storagegateway:CreateTapePool"],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName="sgw-create-list-only", PolicyDocument=json.dumps(policy_doc)
    )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]

    def _as_user():
        return ctx.client(
            "storagegateway",
            creds={
                "aws_access_key_id": key["AccessKeyId"],
                "aws_secret_access_key": key["SecretAccessKey"],
            },
        )

    pool_name = ctx.unique_name("sim2real-sgw-leastpriv-pool-")
    pool_arn_box: dict = {}
    ctx.on_cleanup(lambda: _teardown_pool(ctx, pool_arn_box))

    def _try_create():
        try:
            result = _as_user().create_tape_pool(
                PoolName=pool_name,
                StorageClass="GLACIER",
                RetentionLockType="NONE",
                RetentionLockTimeInDays=0,
            )
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        pool_arn_box["arn"] = result["PoolARN"]
        return "SUCCESS"

    # ---- positive control: the granted action succeeds for this principal once IAM converges ----
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    last_code = _try_create()
    while last_code in _UNCONVERGED and time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_S)
        last_code = _try_create()
    assert last_code == "SUCCESS", (
        f"the granted CreateTapePool never converged for the restricted principal; last code {last_code!r}"
    )
    pool_arn = pool_arn_box["arn"]

    listed = _as_user().list_tape_pools(PoolARNs=[pool_arn])["PoolInfos"]
    assert [p["PoolARN"] for p in listed] == [pool_arn], (
        f"expected only {pool_arn!r}, got {listed!r}"
    )

    # ---- the withheld action is denied for the identical resource and principal ----
    code, message = _error(lambda: _as_user().delete_tape_pool(PoolARN=pool_arn))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException, got {code}: {message!r}"
    )
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"storagegateway:DeleteTapePool on resource: {pool_arn} because no identity-based policy "
        "allows the storagegateway:DeleteTapePool action"
    )
    assert message == expected_message, f"unexpected denial message {message!r}"

    still_there = sg.list_tape_pools(PoolARNs=[pool_arn])["PoolInfos"]
    assert [p["PoolARN"] for p in still_there] == [pool_arn], (
        f"the denied delete must leave the pool in place; got {still_there!r}"
    )

    # ---- positive control: the identical delete succeeds for the unrestricted principal ----
    sg.delete_tape_pool(PoolARN=pool_arn)
    pool_arn_box.pop("arn", None)
    gone = sg.list_tape_pools(PoolARNs=[pool_arn])["PoolInfos"]
    assert gone == [], f"expected the pool gone after the unrestricted delete, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
