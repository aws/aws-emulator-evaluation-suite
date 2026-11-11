"""start-live-tail-mutually-exclusive-stream-filters-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-live-tail-mutually-exclusive-stream-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail rejects logStreamNames plus logStreamNamePrefixes (mutually exclusive) with
    InvalidParameterException on a real log group; a single-filter session is accepted first.
    """
    logs = ctx.client("logs")

    if not hasattr(logs, "start_live_tail"):
        raise AssertionError("unreachable: this boto3 version lacks StartLiveTail")

    group_name = ctx.unique_name("sim2real-livetail-excl-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group(logs, group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName="stream-a")
    logs.create_log_stream(logGroupName=group_name, logStreamName="stream-b")

    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns ARNs with a trailing ":*" wildcard suffix, but StartLiveTail
    # rejects log group ARNs that include that suffix -- it must be stripped first.
    if group_arn.endswith(":*"):
        group_arn = group_arn[: -len(":*")]

    # Positive control: rules out a target that rejects every StartLiveTail call.
    control_resp = logs.start_live_tail(logGroupIdentifiers=[group_arn], logStreamNames=["stream-a"])
    control_event = next(iter(control_resp["responseStream"]))
    assert "sessionStart" in control_event, (
        f"positive control: expected StartLiveTail with a single valid filter to open a "
        f"session (sessionStart), got {control_event!r}"
    )

    code = message = None
    try:
        resp = logs.start_live_tail(
            logGroupIdentifiers=[group_arn],
            logStreamNames=["stream-a"],
            logStreamNamePrefixes=["stream-"],
        )
        for _event in resp["responseStream"]:
            break
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            "expected StartLiveTail with both logStreamNames and logStreamNamePrefixes to be "
            "rejected, but it opened a session"
        )

    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for mutually exclusive logStreamNames/"
        f"logStreamNamePrefixes, got {code!r}: {message!r}"
    )
    assert message == (
        "LogStreamNames provided with LogStreamPrefixes. LogStreamPrefixes is disabled if log "
        "stream names is provided."
    ), f"unexpected mutually-exclusive filter message: {message!r}"


def _delete_log_group(logs_client: Any, group_name: str) -> None:
    try:
        logs_client.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
