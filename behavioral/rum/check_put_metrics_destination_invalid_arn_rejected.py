"""put-metrics-destination-invalid-arn-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-metrics-destination-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRumMetricsDestination for Evidently with a malformed DestinationArn is refused with
    ValidationException and persists nothing, while a CloudWatch destination on the same monitor
    succeeds.
    """
    rum = ctx.client("rum")
    sts = ctx.client("sts")
    app_name = _create_app_monitor(ctx)
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: a valid CloudWatch destination succeeds.
    rum.put_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(
            AppMonitorName=app_name, Destination="CloudWatch"
        )
    )

    # Break exactly one thing: a malformed DestinationArn, with a syntactically-valid
    # (if nonexistent) IamRoleArn so the rejection can only be attributed to the
    # DestinationArn format check, not to IamRoleArn also being malformed.
    bogus_role = f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-role"
    code, message = _client_error(
        lambda: rum.put_rum_metrics_destination(
            AppMonitorName=app_name,
            Destination="Evidently",
            DestinationArn="not-a-valid-arn",
            IamRoleArn=bogus_role,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not-a-valid-arn' at 'destinationArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: .*arn:[^:]*:[^:]*:[^:]*:[^:]*:.*"
    ), message

    # Effect absent: no Evidently destination was persisted, only the CloudWatch one.
    destinations = rum.list_rum_metrics_destinations(AppMonitorName=app_name)["Destinations"]
    kinds = {d["Destination"] for d in destinations}
    assert kinds == {"CloudWatch"}, f"unexpected destinations after rejected put: {destinations}"


def _create_app_monitor(ctx: Any) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-app-")
    rum.create_app_monitor(Name=name, Domain="sim2real.example.com")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
