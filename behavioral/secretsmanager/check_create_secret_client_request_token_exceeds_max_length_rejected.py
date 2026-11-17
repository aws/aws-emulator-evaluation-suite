"""create-secret-client-request-token-exceeds-max-length-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-secret-client-request-token-exceeds-max-length-rejected"
GROUP = "validation"
SERVICES = ["secretsmanager"]


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _refusal(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret refuses a ClientRequestToken one character past its 64-character maximum,
    while a 64-character token at the boundary is accepted and seeds the first version.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-smtok-")
    too_long = "a" * 65

    code, message = _refusal(lambda: sm.create_secret(Name=name, SecretString="initial", ClientRequestToken=too_long))
    assert code == "ValidationException", f"a 65-character ClientRequestToken must be refused, got {code!r}: {message!r}"
    expected = (
        f"1 validation error detected: Value '{too_long[:64]} ...' at 'clientRequestToken' "
        "failed to satisfy constraint: Member must have length less than or equal to 64"
    )
    assert message == expected, f"unexpected message for a too-long ClientRequestToken: {message!r}"

    # Effect absent: the refused call created nothing under the name.
    after = _refusal(lambda: sm.describe_secret(SecretId=name))
    assert after == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"after the refused CreateSecret, DescribeSecret on the name returned {after!r}: "
        f"a refused call created a secret"
    )

    # Positive control: a token at the boundary, 64 characters, is accepted.
    at_boundary = uuid.uuid4().hex + uuid.uuid4().hex[:32]
    assert len(at_boundary) == 64, f"test setup: expected a 64-character token, got {len(at_boundary)}"
    created = sm.create_secret(Name=name, SecretString="initial", ClientRequestToken=at_boundary)
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))
    assert created["VersionId"], f"CreateSecret with a 64-character token must succeed, got {created!r}"
    value = sm.get_secret_value(SecretId=created["ARN"])
    assert value["SecretString"] == "initial", f"the control secret must serve its value, got {value['SecretString']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
