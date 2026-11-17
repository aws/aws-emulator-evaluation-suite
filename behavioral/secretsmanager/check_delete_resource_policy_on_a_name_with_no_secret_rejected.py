"""delete-resource-policy-on-a-name-with-no-secret-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-on-a-name-with-no-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]

_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _refusal(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a name no secret was ever created under fails
    ResourceNotFoundException; creating that same name then makes the identical call succeed.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-smdrp-")

    got = _refusal(lambda: sm.delete_resource_policy(SecretId=name))
    assert got == _NOT_FOUND, f"DeleteResourcePolicy on a never-created name returned {got!r}, expected {_NOT_FOUND!r}"

    got_again = _refusal(lambda: sm.delete_resource_policy(SecretId=name))
    assert got_again == _NOT_FOUND, f"a second refusal on the same name returned {got_again!r}"

    created = sm.create_secret(
        Name=name, SecretString="sim2real-not-a-real-secret",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))

    resp = sm.delete_resource_policy(SecretId=name)
    assert resp.get("Name") == name, (
        f"DeleteResourcePolicy on the now-existing name answered Name {resp.get('Name')!r}, expected {name!r}"
    )

    after = sm.get_resource_policy(SecretId=name)
    assert not after.get("ResourcePolicy"), (
        f"the secret never had a policy attached, so GetResourcePolicy must still report none, "
        f"got {after.get('ResourcePolicy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
