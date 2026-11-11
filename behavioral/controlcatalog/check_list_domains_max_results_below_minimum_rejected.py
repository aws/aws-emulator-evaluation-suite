"""list-domains-max-results-below-minimum-rejected."""
from __future__ import annotations

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-domains-max-results-below-minimum-rejected"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]


_MIN_RESULTS_MESSAGE = (
    "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    "Member must have value greater than or equal to 1"
)


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, so an emulator
    accepting what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects MaxResults=0, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MaxResults below the documented minimum of 1 is rejected by the service itself with
    ValidationException."""
    cc = ctx.client("controlcatalog")
    # Client-side parameter validation mirrors the documented 1-100 bound and would stop
    # MaxResults=0 before the wire, so the service's own rejection needs a validation-disabled client.
    raw = ctx.client("controlcatalog", config=Config(parameter_validation=False))

    code, message = _error_code(lambda: raw.list_domains(MaxResults=0))
    assert code == "ValidationException", f"expected ValidationException from the service, got {code!r}"
    assert message == _MIN_RESULTS_MESSAGE, f"expected {_MIN_RESULTS_MESSAGE!r}, got {message!r}"

    # Positive control: the boundary value 1 (the documented minimum) succeeds.
    response = cc.list_domains(MaxResults=1)
    assert len(response.get("Domains", [])) <= 1


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



