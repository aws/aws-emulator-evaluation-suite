"""deep-logs-2-logcmk-query-result-key-gates-insights."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-query-result-key-gates-insights"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An account-level query-result CMK gates Logs Insights: revoking its Logs grant fails queries
    and disassociating restores them; both selectors at once, or an ungranted key, is rejected.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_AssociateKmsKey.html
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    ident = ctx.client("sts").get_caller_identity()
    account_id = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    query_result_arn = f"arn:{partition}:logs:{ctx.region}:{account_id}:query-result:*"

    full_policy = _key_policy(account_id, ctx.region, grant_logs=True)
    revoked_policy = _key_policy(account_id, ctx.region, grant_logs=False)

    group = ctx.unique_name("sim2real-logcmk-qr-")
    stream = "s1"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    marker = group.rsplit("-", 1)[-1]
    start_ms = int(time.time() * 1000) - 2000
    expected = [f"qr-line {marker} {i}" for i in range(4)]
    logs.put_log_events(logGroupName=group, logStreamName=stream,
                        logEvents=[{"timestamp": start_ms + i, "message": m}
                                   for i, m in enumerate(expected)])

    def query():
        return _run_query(logs, ClientError, group, start_ms, marker)

    baseline = _poll(query, lambda r: r[:2] == ("ok", expected), timeout_s=40, interval_s=3,
                     what="the baseline Insights query to return the 4 ingested lines")
    assert baseline[:2] == ("ok", expected), f"baseline query returned {baseline!r}"

    good_key = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-qr-good-"),
        Policy=full_policy,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=good_key, PendingWindowInDays=7))
    bare_key = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-qr-bare-"),
        Policy=revoked_policy,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=bare_key, PendingWindowInDays=7))
    assert baseline[2] not in (good_key, bare_key), (
        f"a key created after the baseline query was reported as its encryptionKey: {baseline!r}"
    )

    # The query-result association is one per account per region; this restores the account
    # default. Registered before the two calls expected to be rejected, in case one is accepted.
    ctx.on_cleanup(lambda: logs.disassociate_kms_key(resourceIdentifier=query_result_arn))

    # Both selectors at once is a request-shape violation.
    both, both_msg = _error(lambda: logs.associate_kms_key(
        logGroupName=group, resourceIdentifier=query_result_arn, kmsKeyId=good_key), ClientError)
    assert both == "ValidationException", (
        f"AssociateKmsKey with BOTH logGroupName and resourceIdentifier returned {both!r}, "
        "expected ValidationException"
    )
    assert both_msg == "resourceIdentifier should not be specified with any other log group attributes", (
        f"AssociateKmsKey with BOTH selectors returned message {both_msg!r}"
    )
    assert "kmsKeyId" not in _describe_group(logs, group), (
        "the rejected both-selectors call must not have associated the key with the log group"
    )

    # A key CloudWatch Logs was never granted is refused for query results, and nothing changes.
    denied, denied_msg = _error(lambda: logs.associate_kms_key(
        resourceIdentifier=query_result_arn, kmsKeyId=bare_key), ClientError)
    assert denied == "AccessDeniedException", (
        f"query-result association with a key lacking the Logs grant returned {denied!r}, "
        "expected AccessDeniedException"
    )
    expected_denied = (
        "The specified KMS key does not exist or is not allowed to be used with Arn "
        f"'{query_result_arn}'"
    )
    assert denied_msg == expected_denied, (
        f"query-result association with a key lacking the Logs grant returned message {denied_msg!r}, "
        f"expected {expected_denied!r}"
    )
    unaffected = query()
    assert unaffected[:2] == ("ok", expected) and unaffected[2] != bare_key, (
        f"after a REJECTED query-result association, queries returned {unaffected!r}"
    )

    # GetQueryResults names the key as `encryptionKey` on a Complete query. Rows are not asserted
    # here: they can come back empty for a propagation window (documented as up to 5 minutes)
    # longer than the 300s per-check ceiling allows; rows are asserted at baseline and recovery.
    logs.associate_kms_key(resourceIdentifier=query_result_arn, kmsKeyId=good_key)
    with_key = _poll(query, lambda r: r[0] == "ok" and r[2] == good_key, timeout_s=60,
                     interval_s=5,
                     what="a Complete query to report encryptionKey = the query-result CMK")
    assert with_key[0] == "ok" and with_key[2] == good_key, (
        f"query with the CMK associated returned {with_key!r}"
    )

    # The CMK is in the path: revoke its Logs statement and queries fail.
    kms.put_key_policy(KeyId=good_key, PolicyName="default", Policy=revoked_policy)
    broken = _poll(query, lambda r: r[0] == "err", timeout_s=50, interval_s=5,
                   what="queries to fail once the query-result CMK's Logs grant is revoked")
    assert broken[1:3] == ("ResourceNotFoundException", "StartQuery"), (
        f"query with a revoked query-result CMK failed with {broken!r}, "
        "expected ResourceNotFoundException from StartQuery"
    )
    # The backend's Request ID is per call, so it is lifted from the message; every other byte
    # is graded.
    rid = broken[3].rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    expected_broken = (
        "The KMS Key associated with the Account does not have access on query results ARN "
        "(Service: AWSLogs; Status Code: 400; Error Code: ResourceNotFoundException; "
        f"Request ID: {rid}; Proxy: null)"
    )
    assert broken[3] == expected_broken, (
        f"query with a revoked query-result CMK returned message {broken[3]!r}, expected {expected_broken!r}"
    )
    assert "kmsKeyId" not in _describe_group(logs, group), (
        "a query-result association must not appear as a log-group kmsKeyId"
    )

    # Disassociating the account-level key (key still revoked) restores queries and drops the
    # encryptionKey -- proving the failure came from the query-result association, not from the
    # log group or the account.
    logs.disassociate_kms_key(resourceIdentifier=query_result_arn)
    recovered = _poll(query, lambda r: r == ("ok", expected, None), timeout_s=90, interval_s=5,
                      what="queries to recover, with no encryptionKey, after "
                           "DisassociateKmsKey(resourceIdentifier)")
    assert recovered == ("ok", expected, None), (
        f"after disassociation queries returned {recovered!r}"
    )


def _run_query(logs, client_error, group: str, start_ms: int, marker: str):
    """('ok', [messages], encryptionKey) on a Complete query, ('err', code, op, message) on a
    ClientError."""
    qs = f"fields @message | filter @message like /qr-line {marker}/ | sort @timestamp asc"
    try:
        qid = logs.start_query(logGroupNames=[group], startTime=start_ms // 1000 - 60,
                               endTime=int(time.time()) + 60, queryString=qs)["queryId"]
    except client_error as exc:
        return ("err", exc.response["Error"]["Code"], "StartQuery", exc.response["Error"].get("Message", ""))
    deadline = time.monotonic() + 60
    while True:
        try:
            resp = logs.get_query_results(queryId=qid)
        except client_error as exc:
            return ("err", exc.response["Error"]["Code"], "GetQueryResults",
                    exc.response["Error"].get("Message", ""))
        if resp["status"] not in ("Scheduled", "Running"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} still {resp['status']!r} after 60s")
        time.sleep(1)
    if resp["status"] != "Complete":
        return ("status", resp["status"], qid)
    rows = [[f["value"] for f in row if f["field"] == "@message"] for row in resp["results"]]
    return ("ok", [r[0] for r in rows if r], resp.get("encryptionKey"))


def _error(fn, client_error) -> tuple[str, str]:
    """The (code, message) fn() raised; a success raises, because real AWS rejects the call."""
    try:
        fn()
    except client_error as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call unexpectedly SUCCEEDED; real AWS rejects it")


def _key_policy(account_id: str, region: str, *, grant_logs: bool) -> str:
    statements = [
        {
            "Sid": "RootFullAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    if grant_logs:
        statements.append(
            {
                "Sid": "AllowCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": [
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                "Resource": "*",
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _describe_group(logs, group: str) -> dict:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group):
        for g in page["logGroups"]:
            if g["logGroupName"] == group:
                return g
    raise AssertionError(f"log group {group!r} not found by DescribeLogGroups")


def _poll(probe, predicate, *, timeout_s: float, what: str, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
