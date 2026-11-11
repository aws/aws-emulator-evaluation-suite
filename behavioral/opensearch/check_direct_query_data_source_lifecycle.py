"""direct-query-data-source-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "direct-query-data-source-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddDirectQueryDataSource -> Get -> Update -> List -> Delete round-trips its fields, and Get
    after delete raises ValidationException. Direct-query sources need no domain.
    """
    osv = ctx.client("opensearch")
    role_arn = _create_es_trust_role(ctx, "es.amazonaws.com")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _ds_name(ctx, "dq")
    fake_collection_arn = f"arn:aws:aoss:{ctx.region}:{account_id}:collection/sim2realdq0001"

    osv.add_direct_query_data_source(
        DataSourceName=name,
        DataSourceType={"CloudWatchLog": {"RoleArn": role_arn}},
        Description="sim2real behavioral check initial",
        OpenSearchArns=[fake_collection_arn],
        TagList=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: _safe_delete_dq(osv, name))

    got = osv.get_direct_query_data_source(DataSourceName=name)
    assert got["DataSourceName"] == name, f"expected DataSourceName {name!r}, got {got['DataSourceName']!r}"
    assert got["DataSourceType"]["CloudWatchLog"]["RoleArn"] == role_arn, (
        f"expected RoleArn {role_arn!r}, got {got['DataSourceType']['CloudWatchLog']['RoleArn']!r}"
    )
    assert got["Description"] == "sim2real behavioral check initial", (
        f"expected initial Description, got {got['Description']!r}"
    )

    assert name in _list_dq_names(osv), f"{name} missing from ListDirectQueryDataSources after Add"

    osv.update_direct_query_data_source(
        DataSourceName=name,
        DataSourceType={"CloudWatchLog": {"RoleArn": role_arn}},
        Description="sim2real behavioral check updated",
        OpenSearchArns=[fake_collection_arn],
    )

    got_after_update = osv.get_direct_query_data_source(DataSourceName=name)
    assert got_after_update["Description"] == "sim2real behavioral check updated", (
        "UpdateDirectQueryDataSource did not persist the new description"
    )

    osv.delete_direct_query_data_source(DataSourceName=name)

    deadline = time.monotonic() + 60
    while name in _list_dq_names(osv) and time.monotonic() < deadline:
        time.sleep(3)
    assert name not in _list_dq_names(osv), "data source still listed after DeleteDirectQueryDataSource"

    # Get can lag List after delete, so poll; AWS rejects the deleted name with
    # ValidationException rather than ResourceNotFoundException.
    code, message = _poll_for_error(
        lambda: osv.get_direct_query_data_source(DataSourceName=name),
        "ValidationException",
        timeout_s=60,
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "Data source not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _ds_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"sim2real-{prefix}-")
    return raw.replace("-", "_").lower()


def _create_es_trust_role(ctx, principal: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-osrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _list_dq_names(osv) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = osv.list_direct_query_data_sources(**kwargs)
        for ds in resp.get("DirectQueryDataSources", []):
            n = ds.get("DataSourceName")
            if n:
                names.add(n)
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _safe_delete_dq(osv, name: str) -> None:
    try:
        osv.delete_direct_query_data_source(DataSourceName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises, because
    accepting a call AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_for_error(fn, expected_code: str, timeout_s: float = 60.0, interval_s: float = 3.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
