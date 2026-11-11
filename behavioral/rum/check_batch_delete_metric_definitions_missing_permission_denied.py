"""batch-delete-metric-definitions-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-metric-definitions-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteRumMetricDefinitions from a caller without the permission is refused with
    AccessDeniedException and the definition stays retrievable, while a permitted caller deletes it.
    """
    rum = ctx.client("rum")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-rum-metrics-")
    rum.create_app_monitor(
        Name=app_name, Domain="sim2real-behav.example.com", Tags={"Team": "rum-fidelity"}
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=app_name))

    rum.put_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: rum.delete_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
        )
    )

    created = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app_name,
        Destination="CloudWatch",
        MetricDefinitions=[_custom_metric_definition()],
    )
    metric_id = _resolve_metric_id(rum, app_name, created, _custom_metric_definition())

    user_name = ctx.unique_name("sim2real-rum-deny-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    restricted_rum = ctx.client(
        "rum",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    code, message = _retry_until_denied(
        lambda: restricted_rum.batch_delete_rum_metric_definitions(
            AppMonitorName=app_name,
            Destination="CloudWatch",
            MetricDefinitionIds=[metric_id],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"rum:BatchDeleteRumMetricDefinitions on resource: "
        f"arn:aws:rum:{ctx.region}:{ctx.account}:appmonitor/{app_name} because no "
        f"identity-based policy allows the rum:BatchDeleteRumMetricDefinitions action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # Effect absent: the definition is still there, untouched by the denied call.
    still_there = rum.batch_get_rum_metric_definitions(AppMonitorName=app_name, Destination="CloudWatch")
    ids = [d["MetricDefinitionId"] for d in still_there["MetricDefinitions"]]
    assert metric_id in ids, "metric definition disappeared despite the denied delete"

    # Positive control: the properly-permissioned default caller can delete it.
    deleted = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
    )
    assert deleted["Errors"] == [], f"unexpected per-item errors on control delete: {deleted['Errors']}"

    # Independent read at the destination: the control delete actually took effect, not just
    # that the mutating call itself reported no per-item errors.
    gone = rum.batch_get_rum_metric_definitions(AppMonitorName=app_name, Destination="CloudWatch")
    remaining_ids = [d["MetricDefinitionId"] for d in gone["MetricDefinitions"]]
    assert metric_id not in remaining_ids, (
        f"metric definition {metric_id} still present after the permitted delete: {remaining_ids}"
    )


def _resolve_metric_id(rum, app_name: str, create_response: dict, definition: dict, timeout_s: float = 40.0, interval_s: float = 2.0) -> str:
    """BatchCreateRumMetricDefinitions can transiently report the create as neither an error
    nor a returned definition while the metrics destination finishes propagating, even though
    the definition is actually persisted moments later. Trust BatchGetRumMetricDefinitions (the
    read path) as the durable source of truth: if the create call itself returned the
    definition, use that id directly; a genuine per-item validation error is raised immediately;
    otherwise poll the read path for a definition matching this Name/Namespace."""
    if create_response.get("MetricDefinitions"):
        return create_response["MetricDefinitions"][0]["MetricDefinitionId"]
    for err in create_response.get("Errors") or []:
        if err.get("ErrorCode") != "ConflictException":
            raise AssertionError(f"unexpected per-item error creating metric definition: {err}")

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = rum.batch_get_rum_metric_definitions(AppMonitorName=app_name, Destination="CloudWatch")
        for d in got["MetricDefinitions"]:
            if d["Name"] == definition["Name"] and d.get("Namespace") == definition.get("Namespace"):
                return d["MetricDefinitionId"]
        time.sleep(interval_s)
    raise AssertionError("metric definition not found via BatchGetRumMetricDefinitions after create")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the call's error; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _custom_metric_definition() -> dict:
    return {
        "Name": "Sim2RealVisitCount",
        "Namespace": "Sim2RealCustomMetrics",
        "ValueKey": "event_details.visit_count",
        "UnitLabel": "Count",
        "EventPattern": json.dumps({"event_type": ["sim2real_custom_event"]}),
    }


def _retry_until_denied(fn, timeout_s: float = 40.0, interval_s: float = 2.0) -> tuple[str, str]:
    """Freshly created IAM access keys can take a few seconds to propagate; retry the call
    while it is transiently rejected as an unrecognized credential, until it settles into the
    durable AccessDeniedException that the missing IAM permission produces."""
    deadline = time.monotonic() + timeout_s
    last = ("", "")
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] not in ("InvalidClientTokenId", "InvalidAccessKeyId", "UnrecognizedClientException"):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
