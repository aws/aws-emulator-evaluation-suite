"""batch-get-rum-metric-definitions-invalid-destination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-rum-metric-definitions-invalid-destination-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetRumMetricDefinitions refuses a malformed Evidently DestinationArn with
    ValidationException and a well-formed but unregistered one with ResourceNotFoundException;
    neither adds a destination and the CloudWatch destination is unaffected.
    """
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    unregistered_experiment_arn = (
        f"arn:aws:evidently:{ctx.region}:{account_id}:project/sim2real-nonexistent"
        "/experiment/sim2real-nonexistent"
    )

    malformed_code, malformed_message = _client_error(
        lambda: rum.batch_get_rum_metric_definitions(
            AppMonitorName=app["name"], Destination="Evidently", DestinationArn="not-a-valid-arn"
        )
    )
    assert malformed_code == "ValidationException", f"expected ValidationException, got {malformed_code!r}"
    expected_malformed = (
        "1 validation error detected: Value 'not-a-valid-arn' at 'destinationArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: .*arn:[^:]*:[^:]*:[^:]*:[^:]*:.*"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )

    code, message = _client_error(
        lambda: rum.batch_get_rum_metric_definitions(
            AppMonitorName=app["name"],
            Destination="Evidently",
            DestinationArn=unregistered_experiment_arn,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = (
        f"No destination for Rum metric definitions exists on app monitor {app['name']}, "
        "for the specified parameters. Please try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: neither rejected call registered an Evidently destination.
    destinations = rum.list_rum_metrics_destinations(AppMonitorName=app["name"])["Destinations"]
    kinds = {d["Destination"] for d in destinations}
    assert kinds == {"CloudWatch"}, f"unexpected destinations after rejected calls: {destinations}"

    # Positive control (same file): querying the always-available CloudWatch
    # destination on the same, real app monitor succeeds.
    ok_resp = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app["name"], Destination="CloudWatch"
    )
    assert "MetricDefinitions" in ok_resp, f"expected MetricDefinitions key, got {ok_resp!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    kwargs.setdefault("Tags", {"sim2real:managed": "true"})
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _client_error(fn):
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
