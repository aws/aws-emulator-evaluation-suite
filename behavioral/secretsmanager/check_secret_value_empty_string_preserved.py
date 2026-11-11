"""secret-value-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secret-value-empty-string-preserved"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The service itself rejects CreateSecret with an empty SecretString (ValidationException) and
    creates nothing, while a one-character SecretString round-trips exactly."""
    import botocore.exceptions
    from botocore.config import Config

    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-")

    # Positive control: a minimal non-empty SecretString creates and round-trips exactly.
    sm.create_secret(Name=name, SecretString="x", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))
    resp = sm.get_secret_value(SecretId=name)
    assert resp["SecretString"] == "x", f"expected 'x', got {resp['SecretString']!r}"

    # Bypass client-side validation so the empty SecretString actually reaches the service;
    # a local ParamValidationError would say nothing about the service's contract.
    unvalidated = ctx.client("secretsmanager", config=Config(parameter_validation=False))
    rejected_name = ctx.unique_name("sim2real-behav-")
    try:
        unvalidated.create_secret(
            Name=rejected_name, SecretString="", Tags=[{"Key": "sim2real", "Value": CHECK}]
        )
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for an empty SecretString reaching the "
            f"service, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == (
            "1 validation error detected: Value at 'secretString' failed to satisfy constraint: "
            "Member must have length greater than or equal to 1"
        ), f"unexpected empty-SecretString message: {message!r}"
    else:
        ctx.on_cleanup(
            lambda: sm.delete_secret(SecretId=rejected_name, ForceDeleteWithoutRecovery=True)
        )
        raise AssertionError(
            "expected CreateSecret with an empty SecretString to be rejected by the "
            "service, but it succeeded"
        )

    # Effect-absent: the rejected secret must never have come to exist.
    try:
        sm.get_secret_value(SecretId=rejected_name)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected the rejected secret to be absent, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Secrets Manager can't find the specified secret.", (
            f"unexpected not-found message: {message!r}"
        )
    else:
        raise AssertionError(
            "expected the rejected secret to not exist after being refused, but it does"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
