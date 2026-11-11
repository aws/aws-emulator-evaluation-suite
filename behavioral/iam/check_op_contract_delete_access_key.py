"""op-contract-deleteAccessKey."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteAccessKey"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAccessKey removes the key (idempotent read reflects it); NoSuchEntity on unknown id."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-uak-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]

    # success path: delete the key and confirm it disappears from ListAccessKeys
    resp = iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 from DeleteAccessKey, got {status}"
    remaining = [
        k["AccessKeyId"]
        for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    ]
    assert key_id not in remaining, "deleted access key still listed"

    # error boundary: deleting the same (now-nonexistent) key again -> NoSuchEntityException
    code, message = _error(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The Access Key with id {key_id} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # distinct boundary: a well-formed but never-issued AccessKeyId also 404s
    code2, message2 = _error(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId="AKIAZZZZZZZZZZZZZZZZ")
    )
    assert code2 == "NoSuchEntity", f"expected NoSuchEntity, got {code2}"
    expected2 = "The Access Key with id AKIAZZZZZZZZZZZZZZZZ cannot be found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
