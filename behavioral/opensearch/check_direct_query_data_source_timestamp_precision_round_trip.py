"""direct-query-data-source-timestamp-precision-round-trip."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "direct-query-data-source-timestamp-precision-round-trip"
GROUP = "representation"
SERVICES = ["opensearch"]

_SUBSECOND_TIMESTAMP = "2024-06-01T12:34:56.123456789Z"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A nanosecond aws:CurrentTime value in DataSourceAccessPolicy round-trips without truncation.

    Get on a never-created name, and Get/Update after delete, fail with "Data source not found".
    """
    opensearch = ctx.client("opensearch")
    ds_name = _ds_name(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{_short_role_name(ctx)}"
    workspace_arn = f"arn:aws:aps:{ctx.region}:{account_id}:workspace/ws-00000000-0000-0000-0000-000000000000"
    datasource_arn = f"arn:aws:opensearch:{ctx.region}:{account_id}:datasource/{ds_name}"

    # Documented sample access-policy shape plus a sub-second timestamp Condition under test.
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": [
                        "opensearch:StartDirectQuery",
                        "opensearch:GetDirectQuery",
                        "opensearch:CancelDirectQuery",
                        "opensearch:GetDirectQueryResult",
                    ],
                    "Resource": datasource_arn,
                    "Condition": {
                        "DateGreaterThan": {"aws:CurrentTime": _SUBSECOND_TIMESTAMP}
                    },
                }
            ],
        }
    )

    opensearch.add_direct_query_data_source(
        DataSourceName=ds_name,
        DataSourceType={
            "Prometheus": {"RoleArn": role_arn, "WorkspaceArn": workspace_arn}
        },
        DataSourceAccessPolicy=policy,
    )
    ctx.on_cleanup(
        lambda: _ignore_already_gone(
            lambda: opensearch.delete_direct_query_data_source(DataSourceName=ds_name)
        )
    )

    got = opensearch.get_direct_query_data_source(DataSourceName=ds_name)
    # AWS may reserialize the stored policy JSON (key order, whitespace), so compare parsed values.
    parsed = json.loads(got["DataSourceAccessPolicy"])
    round_tripped_ts = parsed["Statement"][0]["Condition"]["DateGreaterThan"]["aws:CurrentTime"]
    assert round_tripped_ts == _SUBSECOND_TIMESTAMP, (
        f"sub-second timestamp precision was lost: {round_tripped_ts!r} != {_SUBSECOND_TIMESTAMP!r}"
    )
    assert parsed["Statement"][0]["Resource"] == datasource_arn, (
        f"policy Resource did not round-trip: {parsed['Statement'][0]['Resource']!r} != {datasource_arn!r}"
    )
    assert parsed["Statement"][0]["Principal"] == {"AWS": f"arn:aws:iam::{account_id}:root"}, (
        f"policy Principal did not round-trip: {parsed['Statement'][0]['Principal']!r}"
    )
    assert set(parsed["Statement"][0]["Action"]) == {
        "opensearch:StartDirectQuery",
        "opensearch:GetDirectQuery",
        "opensearch:CancelDirectQuery",
        "opensearch:GetDirectQueryResult",
    }, f"policy Action set did not round-trip: {parsed['Statement'][0]['Action']!r}"

    # AWS answers an unknown DataSourceName with ValidationException, although the API
    # reference lists ResourceNotFoundException.
    never_created_name = (ds_name + "_never_created")[:80]
    code, message = _error(lambda: opensearch.get_direct_query_data_source(DataSourceName=never_created_name))
    assert code == "ValidationException", (
        f"expected ValidationException for an unknown direct query data source, got {code!r}"
    )
    expected_message = "Data source not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Deletion is not immediately visible to GetDirectQueryDataSource, so the read is polled.
    opensearch.delete_direct_query_data_source(DataSourceName=ds_name)
    deleted_code, deleted_message = _poll_for_error(
        lambda: opensearch.get_direct_query_data_source(DataSourceName=ds_name),
        "ValidationException",
        timeout_s=60,
    )
    assert deleted_code == "ValidationException", (
        f"expected ValidationException reading a deleted direct query data source, got {deleted_code!r}"
    )
    expected_deleted_message = "Data source not found"
    assert deleted_message == expected_deleted_message, (
        f"expected message {expected_deleted_message!r}, got {deleted_message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: opensearch.update_direct_query_data_source(
            DataSourceName=ds_name,
            DataSourceType={
                "Prometheus": {"RoleArn": role_arn, "WorkspaceArn": workspace_arn}
            },
            DataSourceAccessPolicy=policy,
        )
    )
    assert mutate_code == "ValidationException", (
        f"expected UpdateDirectQueryDataSource on a deleted data source to be rejected, got {mutate_code!r}"
    )
    expected_mutate_message = "Data source not found"
    assert mutate_message == expected_mutate_message, (
        f"expected message {expected_mutate_message!r}, got {mutate_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_for_error(fn, expected_code, *, timeout_s=60.0, interval_s=3.0):
    """Poll fn() until it is rejected with expected_code; a success means "not settled yet"."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = ("<succeeded>", None)
        except ClientError as err:
            e = err.response.get("Error", {})
            last = (e.get("Code"), e.get("Message"))
            if last[0] == expected_code:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"never rejected with {expected_code} within {timeout_s}s; last={last!r}")


def _ds_name(ctx) -> str:
    raw = ctx.unique_name("sim2real_dq_").lower()
    cleaned = re.sub(r"[^a-z0-9_]", "_", raw)
    truncated = cleaned[:80].rstrip("_")
    if len(truncated) < 3 or not truncated[0].isalpha():
        truncated = ("dq_" + truncated)[:80]
    return truncated


def _short_role_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-role-")
    return re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", raw)[:64]


def _ignore_already_gone(fn) -> None:
    # Safety net for when an assertion fires before run() deletes the data source itself;
    # this API reports a missing data source as ValidationException.
    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "ValidationException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
