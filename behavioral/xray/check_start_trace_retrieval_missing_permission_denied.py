"""start-trace-retrieval-missing-permission-denied."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-trace-retrieval-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["xray"]

# With the XRay destination there is no "aws/spans" log group, so a permitted call fails with
# ResourceNotFoundException; a 200 (destination switched to CloudWatchLogs) is also IAM-permitted.
_BASELINE_CODE = "ResourceNotFoundException"
_UNBLOCKED = frozenset({_BASELINE_CODE, "UNEXPECTED_SUCCESS"})

_ALLOW_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "xray:*", "Resource": "*"}],
}
_ALLOW_ALL_DENY_RETRIEVAL = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "xray:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "xray:StartTraceRetrieval", "Resource": "*"},
    ],
}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM Deny on xray:StartTraceRetrieval turns that call into AccessDeniedException with the
    exact message while GetSamplingRules still works; before the Deny and after its removal the
    call is IAM-permitted, and the stored policy then has only Allow statements."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-xray-user-")
    user_arn = iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "xray-access"
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_ALLOW_ALL)
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    restricted_xray = ctx.client(
        "xray",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    now = datetime.now(timezone.utc)
    # An empty TraceIds list is rejected ("Zero trace ids provided"); a fabricated id suffices.
    trace_id = f"1-{int(now.timestamp()):08x}-{secrets.token_hex(12)}"

    def _attempt():
        return restricted_xray.start_trace_retrieval(
            TraceIds=[trace_id],
            StartTime=now - timedelta(hours=1),
            EndTime=now,
        )

    before, _ = _poll_until_code(
        _attempt, _UNBLOCKED, timeout_s=90.0,
        description="start_trace_retrieval before any Deny is attached",
    )
    assert before in _UNBLOCKED, (
        f"the identity policy grants xray:StartTraceRetrieval, so the call must reach the "
        f"service layer and land on {sorted(_UNBLOCKED)!r}, not an access-denied outcome, "
        f"before any Deny is attached; got {before!r}"
    )

    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(_ALLOW_ALL_DENY_RETRIEVAL),
    )

    code, message = _poll_until_code(
        _attempt, frozenset({"AccessDeniedException"}), timeout_s=90.0,
        description="start_trace_retrieval once the Deny is attached",
    )
    assert code == "AccessDeniedException", (
        f"expected xray:StartTraceRetrieval to converge on AccessDeniedException once the Deny "
        f"propagates; got {code!r}"
    )
    expected_message = (
        f"User: {user_arn} is not authorized to perform: xray:StartTraceRetrieval with an "
        "explicit deny in an identity-based policy"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    resp = restricted_xray.get_sampling_rules()
    assert "SamplingRuleRecords" in resp, (
        f"an unrelated xray action must still succeed under the same restricted credentials "
        f"while only StartTraceRetrieval is denied; got {resp!r}"
    )

    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_ALLOW_ALL)
    )
    restored, _ = _poll_until_code(
        _attempt, _UNBLOCKED, timeout_s=90.0,
        description="the identical call once the Deny is removed",
    )
    assert restored in _UNBLOCKED, (
        f"removing the Deny must restore an IAM-unblocked outcome ({sorted(_UNBLOCKED)!r}), not "
        f"an access-denied one; got {restored!r}"
    )

    stored = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
    effects = {stmt["Effect"] for stmt in stored["Statement"]}
    assert effects == {"Allow"}, (
        f"the stored policy read back after restore must contain no Deny statement; got "
        f"statements with effects {effects!r} in {stored!r}"
    )


def _poll_until_code(
    fn: Callable[[], Any],
    acceptable: frozenset[str],
    timeout_s: float,
    description: str,
    interval_s: float = 2.0,
) -> tuple[str, str | None]:
    """Poll fn() until its error code is in `acceptable`; -> (code, message), raise on timeout.

    IAM changes are eventually consistent; a success is reported as "UNEXPECTED_SUCCESS"."""
    deadline = time.monotonic() + timeout_s
    code = "UNEXPECTED_SUCCESS"
    while time.monotonic() < deadline:
        message = None
        try:
            fn()
            code = "UNEXPECTED_SUCCESS"
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
        if code in acceptable:
            return code, message
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never converged on {acceptable!r} within {timeout_s}s; "
        f"last observed {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
