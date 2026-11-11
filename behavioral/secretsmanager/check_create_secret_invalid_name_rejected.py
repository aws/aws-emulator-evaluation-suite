"""create-secret-invalid-name-rejected."""
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

CHECK = "create-secret-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret must reject names containing characters outside the allowed set,
    while a syntactically valid name in the same run is still accepted normally."""
    sm = ctx.client("secretsmanager")
    unique = ctx.unique_name("sim2real-behav-badname-")
    bad_name = f"{unique} illegal"  # embedded space is not permitted

    code, message = _refusal(
        lambda: sm.create_secret(Name=bad_name, SecretString="value")
    )
    assert code == "ValidationException", (
        f"a secret name with an illegal character must be rejected, got {code}"
    )
    assert message == (
        "Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!"
    ), f"unexpected refusal message: {message!r}"

    # The illegal name must not have been created under a coerced/sanitized form:
    # a ListSecrets filtered on this run's own unique prefix must find nothing.
    listed = sm.list_secrets(Filters=[{"Key": "name", "Values": [unique]}])
    assert not listed.get("SecretList"), (
        f"a rejected CreateSecret must not leave a secret behind, found {listed['SecretList']}"
    )

    # Positive control: a syntactically valid name is accepted normally, so the
    # rejection above is specific to the illegal character rather than a blanket denial.
    valid_name = ctx.unique_name("sim2real-behav-goodname-")
    created = sm.create_secret(Name=valid_name, SecretString="value")
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=created["ARN"], ForceDeleteWithoutRecovery=True)
    )
    assert created["Name"] == valid_name
    described = sm.describe_secret(SecretId=created["ARN"])
    assert described["Name"] == valid_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
