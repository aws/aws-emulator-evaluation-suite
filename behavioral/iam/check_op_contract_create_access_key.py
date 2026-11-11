"""op-contract-create-access-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-access-key"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAccessKey returns Active keys for the user; a third fails with
    LimitExceeded and its exact message, leaving the two listed keys, and after one
    is deleted the same call issues a new Active key."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _delete_user_with_keys(iam, user_name))

    key1 = iam.create_access_key(UserName=user_name)["AccessKey"]
    assert key1["UserName"] == user_name, f"expected UserName {user_name!r}, got {key1['UserName']!r}"
    assert key1["Status"] == "Active", f"expected new access key Active, got {key1['Status']!r}"
    assert key1["AccessKeyId"] and key1["SecretAccessKey"], (
        f"expected non-empty AccessKeyId/SecretAccessKey, got {key1!r}"
    )

    key2 = iam.create_access_key(UserName=user_name)["AccessKey"]
    assert key2["AccessKeyId"] != key1["AccessKeyId"], (
        f"expected a distinct AccessKeyId for the second key, got {key2['AccessKeyId']!r} twice"
    )

    # break: at the 2-key cap, a third create is rejected
    code, message = _error(lambda: iam.create_access_key(UserName=user_name))
    assert code == "LimitExceeded", f"expected LimitExceeded (max 2 access keys/user), got {code}"
    expected = "Cannot exceed quota for AccessKeysPerUser: 2"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: the rejected create must not have persisted a third key
    listed_ids = {
        k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    }
    assert listed_ids == {key1["AccessKeyId"], key2["AccessKeyId"]}, (
        f"expected exactly the two created keys after the rejected create, got {sorted(listed_ids)}"
    )

    # restore: free a slot, then the identical call must now succeed
    iam.delete_access_key(UserName=user_name, AccessKeyId=key1["AccessKeyId"])
    key3 = iam.create_access_key(UserName=user_name)["AccessKey"]
    assert key3["AccessKeyId"] not in (key1["AccessKeyId"], key2["AccessKeyId"]), (
        f"expected a fresh AccessKeyId after restoring a slot, got {key3['AccessKeyId']!r}"
    )
    assert key3["Status"] == "Active", f"expected restored access key Active, got {key3['Status']!r}"

    listed_after = {
        k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    }
    assert listed_after == {key2["AccessKeyId"], key3["AccessKeyId"]}, (
        f"expected exactly the surviving and restored keys, got {sorted(listed_after)}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_user_with_keys(iam, user_name: str) -> None:
    from botocore.exceptions import ClientError

    for k in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
        iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
