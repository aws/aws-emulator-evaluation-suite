"""update-anomaly-monitor-unknown-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-anomaly-monitor-unknown-arn-rejected"
GROUP = "anomaly-detection"
SERVICES = ["ce"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAnomalyMonitor on an ARN that was never created is rejected with
    UnknownMonitorException, and a real monitor stays updatable afterward.
    """
    ce = ctx.client("ce")

    monitor_name = ctx.unique_name("sim2real-behav-ce-mon-")
    monitor_arn = ce.create_anomaly_monitor(
        AnomalyMonitor={
            "MonitorName": monitor_name,
            "MonitorType": "DIMENSIONAL",
            "MonitorDimension": "SERVICE",
        }
    )["MonitorArn"]
    ctx.on_cleanup(_teardown(
        lambda: ce.delete_anomaly_monitor(MonitorArn=monitor_arn), "UnknownMonitorException"
    ))

    missing_id = str(uuid.uuid4())
    missing_arn = f"arn:aws:ce::{ctx.account}:anomalymonitor/{missing_id}"
    code, message = _error(lambda: ce.update_anomaly_monitor(
        MonitorArn=missing_arn, MonitorName=ctx.unique_name("sim2real-behav-ce-mon-renamed-"),
    ))
    assert code == "UnknownMonitorException", f"expected UnknownMonitorException, got {code}: {message!r}"
    assert message == f"No monitor present with resourceId: {missing_id}", f"unexpected message {message!r}"

    # Positive control: a real monitor is still updatable after the rejection above.
    renamed = ctx.unique_name("sim2real-behav-ce-mon-renamed-")
    ce.update_anomaly_monitor(MonitorArn=monitor_arn, MonitorName=renamed)
    after = ce.get_anomaly_monitors(MonitorArnList=[monitor_arn])["AnomalyMonitors"]
    assert len(after) == 1, f"GetAnomalyMonitors[{monitor_arn!r}] must return exactly one; got {after!r}"
    assert after[0]["MonitorName"] == renamed, (
        f"expected the real monitor to still accept a rename after the rejection, got "
        f"{after[0]['MonitorName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
