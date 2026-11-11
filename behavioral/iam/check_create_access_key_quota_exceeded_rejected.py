"""create-access-key-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-access-key-quota-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A third CreateAccessKey for a user with 2 keys fails with LimitExceeded and the exact
    quota message and leaves the two keys; after one is deleted the same call issues a new
    key."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-akquota-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    key_ids: list[str] = []
    for _ in range(2):
        key = iam.create_access_key(UserName=user_name)["AccessKey"]
        key_ids.append(key["AccessKeyId"])
    for kid in key_ids:
        ctx.on_cleanup(
            lambda k=kid: _safe(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=k))
        )

    listed = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert len(listed) == 2, f"expected exactly 2 access keys after the positive control, got {len(listed)}"

    code, code_msg = _client_error(lambda: iam.create_access_key(UserName=user_name))
    assert code == "LimitExceeded", f"expected LimitExceeded for a 3rd access key, got {code!r}"
    assert code_msg == "Cannot exceed quota for AccessKeysPerUser: 2", f"unexpected error message {code_msg!r}"

    # the rejected call must not have created a third key
    listed_after = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert len(listed_after) == 2, f"expected quota still pinned at 2 after the rejected call, got {len(listed_after)}"
    assert {k["AccessKeyId"] for k in listed_after} == set(key_ids), (
        f"expected the persisted key set unchanged at {sorted(key_ids)}, got "
        f"{sorted(k['AccessKeyId'] for k in listed_after)}"
    )

    # restore: freeing one slot must let the identical call succeed again
    freed_kid = key_ids[0]
    iam.delete_access_key(UserName=user_name, AccessKeyId=freed_kid)
    new_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    new_kid = new_key["AccessKeyId"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=new_kid)))
    assert new_kid != freed_kid, "expected a freshly-issued access key id, not a reused one"
    listed_final = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    final_ids = {k["AccessKeyId"] for k in listed_final}
    assert final_ids == {key_ids[1], new_kid}, (
        f"expected exactly the surviving original key and the new one, got {sorted(final_ids)}"
    )


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
