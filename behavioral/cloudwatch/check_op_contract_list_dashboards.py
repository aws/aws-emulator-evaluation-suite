"""op-contract-listDashboards."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-listDashboards"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards surfaces a created dashboard filtered by prefix; a DashboardNamePrefix
    containing characters outside [A-Za-z0-9._-] is rejected."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cwdash-")
    body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 3,
                "height": 3,
                "properties": {"markdown": "# sim2real behavioral check"},
            }
        ]
    }
    cw.put_dashboard(DashboardName=name, DashboardBody=json.dumps(body))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[name]))

    entries = _poll_until(
        lambda: cw.list_dashboards(DashboardNamePrefix=name).get("DashboardEntries", []),
        lambda entries: len(entries) == 1,
        timeout_s=30,
    )
    assert len(entries) == 1, f"expected exactly 1 dashboard with prefix {name}, got {entries}"
    entry = entries[0]
    assert entry["DashboardName"] == name, f"expected DashboardName {name}, got {entry['DashboardName']}"
    assert entry["DashboardArn"].endswith(f":dashboard/{name}"), (
        f"expected DashboardArn ending :dashboard/{name}, got {entry['DashboardArn']}"
    )
    assert entry["Size"] > 0, f"expected Size > 0, got {entry['Size']}"

    # ListDashboards validates DashboardNamePrefix: characters outside [A-Za-z0-9._-] are
    # rejected.
    err, message = _error(lambda: cw.list_dashboards(DashboardNamePrefix="bad name!"))
    # CloudWatch's awsQuery protocol reports this exception's wire error code as
    # "InvalidParameterValue" (no "Exception" suffix); botocore surfaces that raw
    # code in exc.response["Error"]["Code"].
    assert err == "InvalidParameterValue", f"expected InvalidParameterValue, got {err}"
    expected = (
        "The value for field DashboardNamePrefix contains invalid characters. "
        "It can only contain alphanumerics, dash (-) and underscore (_).\n"
    )
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
