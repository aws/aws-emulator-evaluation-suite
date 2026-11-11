"""add-application-input-on-flink-application-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "add-application-input-on-flink-application-rejected"
GROUP = 'rejected-configuration'
SERVICES = ['kinesisanalyticsv2']

RUNTIME = "FLINK-1_15"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

def _error(fn) -> dict:
    """The AWS error (``Code`` and ``Message``) raised by ``fn``.

    Raises if the call SUCCEEDS: an emulator that accepts input real AWS rejects is the
    strongest signal this check can produce, and returning a sentinel would turn it into
    an error-code mismatch.
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if not response:
            raise
        return response["Error"]
    raise AssertionError("call unexpectedly SUCCEEDED where real AWS rejects it")


def _create_application(ctx, kda, **kwargs) -> dict:
    """CreateApplication, retrying only the IAM-propagation refusal for up to 150 s.

    A role created seconds earlier is not yet assumable by the service, which reports
    `InvalidArgumentException: ... doesn't have sufficient privileges to assume the role`.
    """
    deadline = time.monotonic() + 150
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return kda.create_application(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "sufficient privileges to assume the role" not in msg:
                raise
            last = msg
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"CreateApplication never stopped reporting a non-assumable role: {last}")
        time.sleep(2)


def _delete_application(kda, app: str) -> None:
    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    if detail["ApplicationStatus"] != "DELETING":
        kda.delete_application(ApplicationName=app, CreateTimestamp=detail["CreateTimestamp"])


def _versions(kda, app: str) -> list[int]:
    ids = []
    token = None
    while True:
        kwargs = {"ApplicationName": app, "Limit": 50}
        if token:
            kwargs["NextToken"] = token
        page = kda.list_application_versions(**kwargs)
        ids += [v["ApplicationVersionId"] for v in page.get("ApplicationVersionSummaries", [])]
        token = page.get("NextToken")
        if not token:
            return sorted(ids)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Flink application refuses SQL input configuration with the exact code and message.

    The refusal adds no input and no version; a legal AddApplicationCloudWatchLoggingOption on the
    same application and version still succeeds and advances the version.
    """
    kda = ctx.client("kinesisanalyticsv2")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    app = ctx.unique_name("sim2real-behav-kdav2-")
    role_name = ctx.unique_name("sim2real-behav-kdav2-")
    group = "/sim2real-behav/" + ctx.unique_name("kdav2-")
    stream = "kinesis-analytics-log-stream"

    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    stream_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:log-stream:{stream}"

    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    created = _create_application(
        ctx, kda,
        ApplicationName=app,
        RuntimeEnvironment=RUNTIME,
        ServiceExecutionRole=role["Role"]["Arn"],
        ApplicationDescription="sim2real behavioral rejection check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_application(kda, app))
    assert created["ApplicationDetail"]["ApplicationVersionId"] == 1, (
        f"a newly created application is at version "
        f"{created['ApplicationDetail']['ApplicationVersionId']!r}, expected 1"
    )

    sql_input = {
        "NamePrefix": "SOURCE_SQL_STREAM",
        "KinesisStreamsInput": {
            "ResourceARN": f"arn:aws:kinesis:{ctx.region}:{account}:stream/{app}"},
        "InputSchema": {
            "RecordFormat": {
                "RecordFormatType": "JSON",
                "MappingParameters": {"JSONMappingParameters": {"RecordRowPath": "$"}},
            },
            "RecordColumns": [{"Name": "COL_A", "SqlType": "VARCHAR(16)", "Mapping": "$.a"}],
        },
    }
    err = _error(lambda: kda.add_application_input(
        ApplicationName=app, CurrentApplicationVersionId=1, Input=sql_input))
    assert err["Code"] == "InvalidArgumentException", (
        f"AddApplicationInput on a {RUNTIME} application was refused with {err['Code']!r}, "
        f"expected 'InvalidArgumentException'"
    )
    expected = "You cannot add sql configuration to a Flink application."
    assert err["Message"] == expected, (
        f"AddApplicationInput on a {RUNTIME} application was refused with message "
        f"{err['Message']!r}, expected {expected!r}"
    )

    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    config = detail.get("ApplicationConfigurationDescription", {})
    sql_config = config.get("SqlApplicationConfigurationDescription", {})
    assert not sql_config.get("InputDescriptions"), (
        f"the refused AddApplicationInput still attached inputs: "
        f"{sql_config.get('InputDescriptions')!r}"
    )
    assert detail["ApplicationVersionId"] == 1, (
        f"the refused AddApplicationInput advanced the version pointer to "
        f"{detail['ApplicationVersionId']!r}, expected it to stay at 1"
    )
    assert _versions(kda, app) == [1], (
        f"ListApplicationVersions reports {_versions(kda, app)!r} after a refused call, "
        f"expected [1]"
    )

    # Positive control: the same configuration path, same application, same version, one legal
    # option instead of an illegal one.
    added = kda.add_application_cloud_watch_logging_option(
        ApplicationName=app, CurrentApplicationVersionId=1,
        CloudWatchLoggingOption={"LogStreamARN": stream_arn})
    assert added["ApplicationVersionId"] == 2, (
        f"the legal AddApplicationCloudWatchLoggingOption produced version "
        f"{added['ApplicationVersionId']!r}, expected 2"
    )
    options = added["CloudWatchLoggingOptionDescriptions"]
    assert [o["LogStreamARN"] for o in options] == [stream_arn], (
        f"the logging option records {[o.get('LogStreamARN') for o in options]!r}, "
        f"expected exactly [{stream_arn!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
