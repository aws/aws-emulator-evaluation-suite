"""get-resource-policy-absent-returns-empty-document."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resource-policy-absent-returns-empty-document"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly-created dashboard has no resource-based (sharing) policy attached by
    default: GetResourcePolicy succeeds (it does NOT raise ResourceNotFoundException)
    and returns an empty policyDocument, while resourceArn still echoes the dashboard."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "env", "value": "sim2real-behavioral"}],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    resp = bcm.get_resource_policy(resourceArn=arn)
    assert resp["resourceArn"] == arn, resp
    # an absent policy comes back as an empty-ish JSON document ("" or "{}"), not an error
    assert resp["policyDocument"] in ("", "{}"), resp["policyDocument"]

    # the dashboard itself is unaffected -- it is fully readable regardless of policy state
    dashboard = bcm.get_dashboard(arn=arn)
    assert dashboard["arn"] == arn, dashboard

    # overly-permissive boundary: a malformed (well-formed length, invalid account id) ARN
    # is still rejected server-side
    code, message = _error_code(
        lambda: bcm.get_resource_policy(
            resourceArn="arn:aws:bcm-dashboards::123:dashboard/not-a-real-resource"
        )
    )
    assert code == "ValidationException", code
    assert message == "1 validation error detected: Value 'arn:aws:bcm-dashboards::123:dashboard/not-a-real-resource' at 'resourceArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:aws[-a-z0-9]*:bcm-dashboards::[0-9]{12}:dashboard/(\\*|[-a-z0-9]+)", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )


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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

