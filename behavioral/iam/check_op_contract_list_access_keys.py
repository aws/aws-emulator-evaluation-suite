"""op-contract-listAccessKeys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listAccessKeys"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAccessKeys reflects exactly the access keys created for the user, each reported
    Active with the correct UserName; listing keys for a UserName that doesn't exist yields
    NoSuchEntityException."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-listkeys-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    initial = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert initial == [], f"expected no access keys for a fresh user, got {initial}"

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    assert key["Status"] == "Active", f"expected Active, got {key['Status']}"

    listed = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert len(listed) == 1, f"expected exactly 1 access key, got {listed}"
    assert listed[0]["AccessKeyId"] == key_id, f"expected {key_id}, got {listed[0]['AccessKeyId']}"
    assert listed[0]["UserName"] == user_name, f"expected {user_name}, got {listed[0]['UserName']}"
    assert listed[0]["Status"] == "Active", f"expected Active, got {listed[0]['Status']}"
    assert "CreateDate" in listed[0], f"CreateDate missing from AccessKeyMetadata: {listed[0]}"

    missing_user = ctx.unique_name("sim2real-listkeys-missing-")
    code, message = _error(lambda: iam.list_access_keys(UserName=missing_user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {missing_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
