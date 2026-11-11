"""max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClusters rejects MaxResults below 20 and above 100 with InvalidParameterValueException "Invalid
    value for max records. Must be between 20 and 100", while an in-range value returns Clusters."""
    dax = ctx.client("dax")

    below_code, below_message = _expect_error(lambda: dax.describe_clusters(MaxResults=5))
    assert below_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for MaxResults=5 (below the documented "
        f"minimum of 20), got {below_code!r}"
    )
    assert below_message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message: {below_message!r}"
    )

    above_code, above_message = _expect_error(lambda: dax.describe_clusters(MaxResults=101))
    assert above_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for MaxResults=101 (above the documented "
        f"maximum of 100), got {above_code!r}"
    )
    assert above_message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message: {above_message!r}"
    )

    resp = dax.describe_clusters(MaxResults=20)
    assert "Clusters" in resp, f"expected a 'Clusters' key in the response, got keys={list(resp)!r}"


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
