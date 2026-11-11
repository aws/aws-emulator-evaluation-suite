"""start-live-tail-invalid-log-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-live-tail-invalid-log-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail against a log group ARN that does not exist is rejected with
    ResourceNotFoundException rather than silently opening an empty/always-idle stream,
    while the identical call against a real, existing log group succeeds."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: the identical call against a REAL log group must succeed --
    # otherwise a rejection on the fake ARN below is indistinguishable from "this
    # caller is rejected on every StartLiveTail call".
    group_name = ctx.unique_name("sim2real-behav-livetail-ctrl-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group(logs, group_name))
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    real_arn = raw_arn[:-2] if raw_arn.endswith(":*") else raw_arn

    try:
        control_stream = logs.start_live_tail(logGroupIdentifiers=[real_arn])["responseStream"]
    except ClientError as exc:
        raise AssertionError(
            "positive control: StartLiveTail on a real, existing log group was rejected: "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from exc
    control_stream.close()

    fake_name = ctx.unique_name("sim2real-behav-nonexistent-lg-")
    fake_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{fake_name}"

    code, message = _error_code(lambda: logs.start_live_tail(logGroupIdentifiers=[fake_arn]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent log group ARN, got {code}: {message!r}"
    )
    assert message == "Provided LogGroup doesn't exist.", f"unexpected not-found message: {message!r}"


def _delete_log_group(logs_client, group_name):
    try:
        logs_client.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
