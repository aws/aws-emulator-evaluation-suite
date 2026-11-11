"""get-dataset-readonly-reflects-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-dataset-readonly-reflects-configuration"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDataset is a pure readonly reflection of dataset state; repeated reads are stable and
    a malformed DatasetIdentifier is rejected rather than silently returning a resource."""
    cw = ctx.client("cloudwatch")

    first = cw.get_dataset(DatasetIdentifier="default")
    second = cw.get_dataset(DatasetIdentifier="default")

    assert first["DatasetId"] == "default" == second["DatasetId"]
    assert first["Arn"] == second["Arn"], "GetDataset ARN must be stable across reads"
    assert first["Arn"].endswith(":dataset/default")
    # KmsKeyArn presence/absence must agree across the two reads (no read-to-read drift
    # from a pure, uncorrelated read path).
    assert ("KmsKeyArn" in first) == ("KmsKeyArn" in second)
    if "KmsKeyArn" in first:
        assert first["KmsKeyArn"] == second["KmsKeyArn"]

    # The ARN form of the identifier is also accepted and must resolve to the same resource.
    arn_form = first["Arn"]
    by_arn = cw.get_dataset(DatasetIdentifier=arn_form)
    assert by_arn["DatasetId"] == "default"
    assert by_arn["Arn"] == arn_form

    # A malformed identifier value must be rejected, not silently treated as "default". The
    # DatasetIdentifier pattern only admits "default" or the dataset's own ARN, so a string matching
    # neither is refused server-side with a specific ValidationError.
    code, message = _error_code(lambda: cw.get_dataset(DatasetIdentifier="not-a-real-dataset-identifier"))
    assert code == "ValidationError", f"expected ValidationError for a malformed DatasetIdentifier, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not-a-real-dataset-identifier' at 'datasetIdentifier' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "(default|arn:[a-zA-Z0-9-]+:cloudwatch:[a-zA-Z0-9-]*:\\d{12}:dataset/default)"
    ), f"unexpected ValidationError message {message!r}"


def _error_code(fn):
    """Return (code, message) for the ClientError fn() raises; raise if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
