"""list-dashboards-invalid-parameter-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-dashboards-invalid-parameter-value-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDashboards with a DashboardNamePrefix holding characters outside alphanumerics, '-' and '_' is
    rejected by the service with InvalidParameterValue and its exact message, while a valid prefix
    lists the check's one dashboard."""
    cw = ctx.client("cloudwatch")

    # Positive control: the account and ListDashboards are otherwise healthy, so the
    # negative below cannot be "this account rejects everything".
    name = ctx.unique_name("sim2real-cwlddip-")
    body = json.dumps({"widgets": []})
    cw.put_dashboard(DashboardName=name, DashboardBody=body)
    ctx.on_cleanup(lambda: _safe_delete_dashboard(cw, name))

    found = _poll_until(
        lambda: cw.list_dashboards(DashboardNamePrefix=name).get("DashboardEntries", []),
        lambda entries: len(entries) == 1,
        timeout_s=30,
    )
    assert len(found) == 1, f"positive control: expected 1 dashboard for prefix {name!r}, got {found}"

    invalid_prefix = "bad:prefix/with#illegal*chars!"
    err = _client_error(lambda: cw.list_dashboards(DashboardNamePrefix=invalid_prefix))
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for DashboardNamePrefix={invalid_prefix!r}, got {err}"
    )
    assert err.get("Message") == 'The value for field DashboardNamePrefix contains invalid characters. It can only contain alphanumerics, dash (-) and underscore (_).\n', f"unexpected message: {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_dashboard(cw, name):
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
