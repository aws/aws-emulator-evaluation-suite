"""op-contract-listTagsForResource-dashboard."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource-dashboard"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a dashboard ARN returns exactly the tag set at PutDashboard, and on a
    well-formed ARN of a nonexistent dashboard raises ResourceNotFoundException with an empty message."""
    cw = ctx.client("cloudwatch")

    name = ctx.unique_name("sim2real-cwtagdash-").replace("-", "_")
    body = {"widgets": [{"type": "text", "x": 0, "y": 0, "width": 3, "height": 3, "properties": {"markdown": "hi"}}]}
    cw.put_dashboard(
        DashboardName=name,
        DashboardBody=json.dumps(body),
        Tags=[{"Key": "sim2real-owner", "Value": "cw-batch-04-dup"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_dashboard(cw, name))

    entries = cw.list_dashboards(DashboardNamePrefix=name)["DashboardEntries"]
    assert len(entries) == 1, f"expected exactly one dashboard matching prefix {name!r}, got {entries}"
    dashboard_arn = entries[0]["DashboardArn"]

    # success-path contract: the tag set at creation is returned exactly
    tags = cw.list_tags_for_resource(ResourceARN=dashboard_arn)["Tags"]
    assert tags == [{"Key": "sim2real-owner", "Value": "cw-batch-04-dup"}], tags

    # error boundary: a syntactically valid dashboard ARN naming a nonexistent dashboard
    missing_arn = dashboard_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("nonexistent_dashboard_")
    code, message = _error(lambda: cw.list_tags_for_resource(ResourceARN=missing_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # real AWS sends this refusal with an empty message
    assert message == "", f"expected an empty refusal message, got {message!r}"


def _safe_delete_dashboard(cw, name):
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
