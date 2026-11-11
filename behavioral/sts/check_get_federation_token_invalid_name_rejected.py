"""get-federation-token-invalid-name-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-invalid-name-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A federated user Name outside the allowed character pattern must be rejected."""

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a rejection, but the call succeeded with {result!r}")

    # Client-side parameter validation is off so the SERVICE's own input validation error
    # surfaces instead of a local ParamValidationError.
    client = ctx.client(
        "sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False)
    )

    # Positive control: the same call shape with a valid Name succeeds, on an account that
    # can otherwise call GetFederationToken -- so the rejection below is attributable to the
    # invalid Name, not to the account/credentials being unable to call it at all.
    control = client.get_federation_token(
        Name=ctx.unique_name("sim2real-behav-fed-"), DurationSeconds=900
    )
    assert control["Credentials"]["SessionToken"], control

    bad_name = "bad name with spaces!"
    code, message = _error(
        lambda: client.get_federation_token(Name=bad_name, DurationSeconds=900)
    )
    assert code == "ValidationError", (
        f"expected ValidationError for an invalid federated user Name, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
