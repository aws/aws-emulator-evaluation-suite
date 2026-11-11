"""create-secret-both-string-and-binary-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _refusal(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")

CHECK = "create-secret-both-string-and-binary-rejected"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret must reject supplying both SecretString and SecretBinary."""
    sm = ctx.client("secretsmanager")

    # Positive control: the same shape of call with only SecretString succeeds, so a
    # rejection below cannot be confused with an account/credentials problem that
    # rejects every CreateSecret regardless of parameters.
    control_name = ctx.unique_name("sim2real-behav-secret-control-")
    control = sm.create_secret(Name=control_name, SecretString="a-string")
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=control["ARN"], ForceDeleteWithoutRecovery=True)
    )
    assert control["Name"] == control_name, (
        f"positive control CreateSecret must succeed and echo the name, got {control!r}"
    )

    name = ctx.unique_name("sim2real-behav-secret-")
    code, message = _refusal(
        lambda: sm.create_secret(
            Name=name, SecretString="a-string", SecretBinary=b"some-bytes"
        )
    )
    assert code == "InvalidParameterException", (
        f"specifying both SecretString and SecretBinary must be rejected, got {code}"
    )
    assert message == (
        "You can't specify both a binary secret value and a string secret value in the same secret."
    ), f"unexpected refusal message: {message!r}"

    # the rejected call must not have created the secret
    not_found, not_found_message = _refusal(lambda: sm.describe_secret(SecretId=name))
    assert not_found == "ResourceNotFoundException", (
        f"a rejected CreateSecret must not leave a secret behind, got {not_found}"
    )
    assert not_found_message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
