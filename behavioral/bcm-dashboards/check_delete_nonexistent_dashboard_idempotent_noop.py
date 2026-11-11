"""delete-nonexistent-dashboard-idempotent-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-dashboard-idempotent-noop"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDashboard declares no ResourceNotFoundException in its model: calling it a
    second time on an already-deleted (well-formed) ARN must succeed as a no-op rather
    than raise, matching the operation's declared error contract."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(name=name, widgets=[_cost_widget("W1")])["arn"]

    # positive control: first delete of a real dashboard succeeds
    bcm.delete_dashboard(arn=arn)

    # the dashboard is now gone (confirmed via GetDashboard -> NotFound)
    code, message = _client_error(lambda: bcm.get_dashboard(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource {arn} does not exist.", message

    # deleting the same, now-nonexistent ARN again must NOT raise
    resp = bcm.delete_dashboard(arn=arn)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # independent terminal read: the no-op delete did not resurrect the dashboard
    code, message = _client_error(lambda: bcm.get_dashboard(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource {arn} does not exist.", message


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what real AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
