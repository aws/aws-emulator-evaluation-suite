"""create-dashboard-double-space-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-dashboard-double-space-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDashboard rejects a name containing a double space (the name pattern
    forbids "  ") with ValidationException; no dashboard is created as a side effect;
    a same-length, single-spaced name in the same file succeeds normally."""
    bcm = ctx.client("bcm-dashboards")

    bad_name = ctx.unique_name("sim2real-dash-") + "  bad"  # double space -> illegal
    code, message = _client_error(
        lambda: bcm.create_dashboard(name=bad_name, widgets=[_cost_widget("W1")])
    )
    assert code == "ValidationException", code
    # AWS answers this validation error with the rejected value quoted or with it left out.
    constraint = (
        "at 'name' failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "(?!.* {2})[a-zA-Z][a-zA-Z0-9 _-]{0,48}[a-zA-Z0-9_-]"
    )
    quoted, unquoted = (
        "1 validation error detected: Value '" + bad_name + "' " + constraint,
        "1 validation error detected: Value " + constraint,
    )
    expected_message = quoted if message.startswith("1 validation error detected: Value '") else unquoted
    assert message == expected_message, message

    assert bad_name not in _list_all_dashboard_names(bcm), (
        "a dashboard was created despite the rejected name"
    )

    # positive control: a validly-formed name in the same call shape succeeds
    good_name = ctx.unique_name("sim2real-dash-") + " ok"
    arn = bcm.create_dashboard(name=good_name, widgets=[_cost_widget("W1")])["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))
    fetched_name = bcm.get_dashboard(arn=arn)["name"]
    assert fetched_name == good_name, f"expected name {good_name!r}, got {fetched_name!r}"


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


def _list_all_dashboard_names(bcm) -> set[str]:
    out: set[str] = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = bcm.list_dashboards(maxResults=100, **kwargs)
        out.update(d["name"] for d in resp["dashboards"])
        token = resp.get("nextToken")
        if not token:
            break
    return out


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
