"""iam-access-key-crud."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "iam-access-key-crud"
GROUP = 'access_keys'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAccessKey -> ListAccessKeys shows it (AKIA prefix) -> DeleteAccessKey -> gone,
    unusable via an independent read, and unmutable."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))

    resp = iam.create_access_key(UserName=user)
    key = resp["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda u=user, k=key_id: _ignore_no_such_entity(
            lambda: iam.delete_access_key(UserName=u, AccessKeyId=k)
        )
    )

    assert key_id.startswith("AKIA"), f"expected AKIA-prefixed access key id, got {key_id!r}"
    assert key.get("SecretAccessKey"), "expected a SecretAccessKey in the CreateAccessKey response"
    assert key["Status"] == "Active", f"expected new access key Active, got {key['Status']!r}"
    assert key["UserName"] == user

    listed = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    assert any(k["AccessKeyId"] == key_id for k in listed), (
        f"created access key {key_id} not present in ListAccessKeys: {listed}"
    )

    # positive control: while the key is live, GetAccessKeyLastUsed (a different
    # op than Create/List/Delete) resolves it back to the owning user.
    live = iam.get_access_key_last_used(AccessKeyId=key_id)
    assert live["UserName"] == user, (
        f"expected GetAccessKeyLastUsed to resolve {key_id} to {user!r}, got {live['UserName']!r}"
    )

    iam.delete_access_key(UserName=user, AccessKeyId=key_id)

    after = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    assert not any(k["AccessKeyId"] == key_id for k in after), (
        f"access key {key_id} still listed after DeleteAccessKey: {after}"
    )

    # gone via a second, independent op. Measured against real AWS: unlike
    # ListAccessKeys/UpdateAccessKey, GetAccessKeyLastUsed reports AccessDenied
    # (not NoSuchEntity) once the id no longer resolves to an owning user.
    code, message = _error(lambda: iam.get_access_key_last_used(AccessKeyId=key_id))
    assert code == "AccessDenied", (
        f"expected AccessDenied from GetAccessKeyLastUsed on a deleted key, got {code!r}"
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f"User: {caller_arn} is not authorized to perform iam:GetAccessKeyLastUsed "
        f"on resource: access key {key_id}"
    )
    assert message == expected, f"GetAccessKeyLastUsed message: {message!r}"

    # a mutation on the dead id also fails, not just a read.
    code, message = _error(
        lambda: iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity from UpdateAccessKey on a deleted key, got {code!r}"
    )
    assert message == f"The Access Key with id {key_id} cannot be found.", (
        f"UpdateAccessKey message: {message!r}"
    )


def _ignore_no_such_entity(fn):
    """Teardown-only: tolerate the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
