"""delete-dashboard-removes-it."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-dashboard-removes-it"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteDashboard, GetDashboard on the same ARN raises ResourceNotFoundException,
    and the dead ARN is not just unreadable but unusable: UpdateDashboard against it fails
    with the same specific error rather than silently applying."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(name=name, widgets=[_cost_widget("W1")])["arn"]

    bcm.delete_dashboard(arn=arn)

    code, message = _client_error(lambda: bcm.get_dashboard(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource {arn} does not exist.", message

    update_code, update_message = _client_error(
        lambda: bcm.update_dashboard(arn=arn, name=name, widgets=[_cost_widget("W2")])
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == f"Dashboard not found: {arn}", update_message


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
