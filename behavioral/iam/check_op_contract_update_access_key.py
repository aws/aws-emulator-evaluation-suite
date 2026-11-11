"""op-contract-updateAccessKey."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-updateAccessKey"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAccessKey: Active<->Inactive status toggle is durable, and a
    well-formed-but-nonexistent AccessKeyId is rejected with NoSuchEntity."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-uak-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    assert key["Status"] == "Active"

    # Success path: Active -> Inactive
    iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")
    status = _key_status(iam, user_name, key_id)
    assert status == "Inactive", f"expected Inactive after update, got {status}"

    # Success path: Inactive -> Active (round trip)
    iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Active")
    status = _key_status(iam, user_name, key_id)
    assert status == "Active", f"expected Active after round-trip update, got {status}"

    # Error boundary: well-formed but nonexistent AccessKeyId -> NoSuchEntityException
    bogus_key_id = "AKIA" + ("0" * 16)
    code, message = _error(
        lambda: iam.update_access_key(
            UserName=user_name, AccessKeyId=bogus_key_id, Status="Inactive"
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for bogus AccessKeyId, got {code}"
    expected = f"The Access Key with id {bogus_key_id} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected call must not have touched the real key's state.
    status = _key_status(iam, user_name, key_id)
    assert status == "Active", f"real key status must be unaffected by rejected update, got {status}"


def _key_status(iam, user_name: str, key_id: str) -> str:
    metas = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    for m in metas:
        if m["AccessKeyId"] == key_id:
            return m["Status"]
    raise AssertionError(f"access key {key_id} not found in ListAccessKeys")


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
