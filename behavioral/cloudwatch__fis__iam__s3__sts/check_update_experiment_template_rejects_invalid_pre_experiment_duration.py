"""update-experiment-template-rejects-invalid-pre-experiment-duration."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-experiment-template-rejects-invalid-pre-experiment-duration"
GROUP = "template"
SERVICES = ["cloudwatch", "fis", "iam", "s3", "sts"]

_INVALID_DURATION = (
    "ValidationException",
    "The preExperimentDuration parameter value for the experimentReportConfiguration is "
    "invalid. Specify a valid duration value and try again.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Call ``fn`` and assert it raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"].get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code!r} ({message!r}), but the call succeeded and returned {result!r}")


def _fis_trusted_role(ctx) -> str:
    """An IAM role FIS's own service principal may assume; FIS only records this ARN on the
    template, it never runs here, so no inline permissions are attached."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fisrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role["Arn"]


def _report_output_bucket(ctx) -> str:
    """An S3 bucket to name as the report's output destination."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fisreports-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    return bucket


def _report_data_source_arn(ctx) -> str:
    """A CloudWatch dashboard ARN to name as the report's data source."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    dashboard = ctx.unique_name("sim2real-behav-fisboard-")
    cw.put_dashboard(DashboardName=dashboard, DashboardBody=json.dumps({"widgets": []}))
    ctx.on_cleanup(_teardown(lambda: cw.delete_dashboards(DashboardNames=[dashboard]), "ResourceNotFound"))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:cloudwatch::{account}:dashboard/{dashboard}"


def _create_template(ctx, fis, role_arn: str) -> str:
    """A minimal, targetless experiment template with no report configuration of its own."""
    template = fis.create_experiment_template(
        clientToken=ctx.unique_name("sim2real-behav-fistmpl-"),
        description="sim2real behavioral template for report-configuration validation",
        roleArn=role_arn,
        stopConditions=[{"source": "none"}],
        targets={},
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
    )["experimentTemplate"]
    ctx.on_cleanup(
        _teardown(lambda: fis.delete_experiment_template(id=template["id"]), "ResourceNotFoundException")
    )
    return template["id"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentTemplate rejects an experimentReportConfiguration whose preExperimentDuration
    is not a valid duration, leaves the template without a report configuration, and a later update
    carrying a valid duration stores it."""
    fis = ctx.client("fis")
    role_arn = _fis_trusted_role(ctx)
    bucket = _report_output_bucket(ctx)
    dashboard_arn = _report_data_source_arn(ctx)
    template_id = _create_template(ctx, fis, role_arn)

    before = fis.get_experiment_template(id=template_id)["experimentTemplate"]
    assert "experimentReportConfiguration" not in before, (
        f"a freshly created template already carries a report configuration: "
        f"{before.get('experimentReportConfiguration')!r}"
    )

    outputs = {"s3Configuration": {"bucketName": bucket, "prefix": "reports/"}}
    data_sources = {"cloudWatchDashboards": [{"dashboardIdentifier": dashboard_arn}]}

    expect_error(
        lambda: fis.update_experiment_template(
            id=template_id,
            experimentReportConfiguration={
                "preExperimentDuration": "not-a-duration",
                "outputs": outputs,
                "dataSources": data_sources,
            },
        ),
        *_INVALID_DURATION,
    )

    after_refusal = fis.get_experiment_template(id=template_id)["experimentTemplate"]
    assert "experimentReportConfiguration" not in after_refusal, (
        f"the rejected update left a report configuration on the template: "
        f"{after_refusal.get('experimentReportConfiguration')!r}"
    )

    updated = fis.update_experiment_template(
        id=template_id,
        experimentReportConfiguration={
            "preExperimentDuration": "PT5M",
            "outputs": outputs,
            "dataSources": data_sources,
        },
    )["experimentTemplate"]
    assert updated["experimentReportConfiguration"]["preExperimentDuration"] == "PT5M", (
        f"the valid update's own response carries {updated.get('experimentReportConfiguration')!r}"
    )

    after_control = fis.get_experiment_template(id=template_id)["experimentTemplate"]
    assert after_control["experimentReportConfiguration"]["preExperimentDuration"] == "PT5M", (
        f"GetExperimentTemplate shows {after_control.get('experimentReportConfiguration')!r} "
        "after the valid update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
