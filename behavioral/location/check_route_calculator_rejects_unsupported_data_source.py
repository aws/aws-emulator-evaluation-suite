"""route-calculator-rejects-unsupported-data-source."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-calculator-rejects-unsupported-data-source"
GROUP = 'routes'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteCalculator accepts only the documented data source providers and
    rejects an unknown one before creating anything, while a valid one still works.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_CreateRouteCalculator.html
    """
    loc = ctx.client("location")
    bad_name = ctx.unique_name("sim2real-behav-location-routecalc-bad-")
    good_name = ctx.unique_name("sim2real-behav-location-routecalc-good-")

    try:
        loc.create_route_calculator(CalculatorName=bad_name, DataSource="Bing")
        raise AssertionError("expected an unsupported DataSource to be rejected")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        assert err["Message"] == "'DataSource' must be one of Esri, Grab, Here.", (
            f"unexpected message {err['Message']!r}"
        )

    try:
        loc.describe_route_calculator(CalculatorName=bad_name)
        raise AssertionError("expected the rejected calculator to have never been created")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the never-created calculator, "
            f"got {exc.response['Error']['Code']!r}"
        )

    loc.create_route_calculator(CalculatorName=good_name, DataSource="Esri")
    ctx.on_cleanup(_teardown(lambda: loc.delete_route_calculator(CalculatorName=good_name),
                              "ResourceNotFoundException"))
    described = loc.describe_route_calculator(CalculatorName=good_name)
    assert described["DataSource"] == "Esri", f"expected DataSource 'Esri', got {described['DataSource']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
