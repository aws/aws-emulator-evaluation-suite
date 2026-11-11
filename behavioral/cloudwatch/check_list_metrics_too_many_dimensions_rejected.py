"""list-metrics-too-many-dimensions-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-metrics-too-many-dimensions-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMetrics rejects a Dimensions filter list of 31 entries, past the 30-dimension ceiling,
    with an exact InvalidParameterValue, while a single dimension filter succeeds."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")

    positive = cw.list_metrics(
        Namespace=namespace, Dimensions=[{"Name": "Dim0", "Value": "v"}]
    )
    assert "Metrics" in positive, (
        f"positive control: expected ListMetrics with a single dimension filter to succeed, "
        f"got {positive!r}"
    )

    # The documented 10-filter cap is not enforced; the 30-dimension-per-metric ceiling is.
    too_many_dims = [{"Name": f"Dim{i}", "Value": "v"} for i in range(31)]
    error = _error(lambda: cw.list_metrics(Namespace=namespace, Dimensions=too_many_dims))
    assert error == ("InvalidParameterValue", "The collection Dimensions must not have a size greater than 30."), (
        f"expected the InvalidParameterValue rejection for 31 dimension filters, got {error!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListMetrics to reject this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
