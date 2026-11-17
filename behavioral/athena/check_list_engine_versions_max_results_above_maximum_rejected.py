"""list-engine-versions-max-results-above-maximum-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-engine-versions-max-results-above-maximum-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEngineVersions rejects MaxResults above the documented maximum of 10 with
    InvalidRequestException instead of clamping it, and accepts MaxResults=10."""
    # Client-side parameter validation would otherwise short-circuit this before it ever
    # reaches the wire (MaxResults carries a min:1/max:10 range constraint in the model),
    # so use a client with validation disabled to actually exercise the server-side rejection.
    athena = _unvalidated_client(ctx, "athena")

    code, message = _error(lambda: athena.list_engine_versions(MaxResults=11))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for MaxResults=11 (above the documented max of 10), "
        f"got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 10"
    ), f"unexpected ListEngineVersions message: {message!r}"

    resp = athena.list_engine_versions(MaxResults=10)
    versions = resp["EngineVersions"]
    assert len(versions) <= 10, (
        f"expected at most 10 entries for MaxResults=10 (the documented maximum), got "
        f"{len(versions)}"
    )
    assert len(versions) > 0, "expected MaxResults=10 (the documented maximum) to be accepted"
    for entry in versions:
        assert entry.get("SelectedEngineVersion"), (
            f"expected a non-empty SelectedEngineVersion in every entry, got {entry!r}"
        )


def _unvalidated_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
