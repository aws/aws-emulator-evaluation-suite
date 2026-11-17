"""experiment-template-logging-report-and-options-configuration."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-template-logging-report-and-options-configuration"
GROUP = "experiment-template"
SERVICES = ["cloudwatch", "fis", "iam", "s3", "sts"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_template(fis, template_id: str) -> None:
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_template(fis, role_arn: str, client_token: str, description: str, extra: dict,
                      *, tries: int = 10, delay_s: float = 3.0) -> dict:
    """CreateExperimentTemplate with a targetless wait action, retried past IAM role
    propagation lag at this, the role's first use."""
    kwargs = dict(
        clientToken=client_token,
        description=description,
        roleArn=role_arn,
        stopConditions=[{"source": "none"}],
        targets={},
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        **extra,
    )
    last_exc = None
    deadline = time.monotonic() + tries * delay_s
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(**kwargs)["experimentTemplate"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"]["Message"]
            if code == "ResourceNotFoundException" or (
                code == "ValidationException" and "assume role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExperimentTemplate persists logConfiguration, experimentOptions and
    experimentReportConfiguration, and GetExperimentTemplate returns every field. A
    sibling with no experimentOptions defaults to "fail", and an Update is visible on the next Get.
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")
    fis = ctx.client("fis")

    account = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-fis-opts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    bucket = ctx.unique_name("sim2real-fis-opts-bucket-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    dashboard = ctx.unique_name("sim2real-fis-opts-dashboard-")
    cw.put_dashboard(DashboardName=dashboard, DashboardBody=json.dumps({"widgets": []}))
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dashboard]))
    dashboard_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dashboard}"

    log_configuration = {
        "s3Configuration": {"bucketName": bucket, "prefix": "logs/"},
        "logSchemaVersion": 2,
    }
    experiment_options = {"accountTargeting": "single-account", "emptyTargetResolutionMode": "skip"}
    report_configuration = {
        "outputs": {"s3Configuration": {"bucketName": bucket, "prefix": "reports/"}},
        "dataSources": {"cloudWatchDashboards": [{"dashboardIdentifier": dashboard_arn}]},
        "preExperimentDuration": "PT1M",
        "postExperimentDuration": "PT1M",
    }

    main_token = ctx.unique_name("sim2real-fis-opts-token-")
    main = _create_template(
        fis, role_arn, main_token, "sim2real experiment template options and report configuration",
        {
            "logConfiguration": log_configuration,
            "experimentOptions": experiment_options,
            "experimentReportConfiguration": report_configuration,
        },
    )
    main_id = main["id"]
    ctx.on_cleanup(lambda: _delete_template(fis, main_id))

    assert main["logConfiguration"] == log_configuration, (
        f"create echoed logConfiguration {main['logConfiguration']!r}, expected {log_configuration!r}"
    )
    assert main["experimentOptions"] == experiment_options, (
        f"create echoed experimentOptions {main['experimentOptions']!r}, expected {experiment_options!r}"
    )
    assert main["experimentReportConfiguration"] == report_configuration, (
        f"create echoed experimentReportConfiguration {main['experimentReportConfiguration']!r}, "
        f"expected {report_configuration!r}"
    )

    got_main = fis.get_experiment_template(id=main_id)["experimentTemplate"]
    assert got_main["logConfiguration"] == log_configuration, (
        f"get returned logConfiguration {got_main['logConfiguration']!r}, expected {log_configuration!r}"
    )
    assert got_main["experimentOptions"] == experiment_options, (
        f"get returned experimentOptions {got_main['experimentOptions']!r}, expected {experiment_options!r}"
    )
    assert got_main["experimentReportConfiguration"] == report_configuration, (
        f"get returned experimentReportConfiguration {got_main['experimentReportConfiguration']!r}, "
        f"expected {report_configuration!r}"
    )

    sibling_token = ctx.unique_name("sim2real-fis-opts-sibling-token-")
    sibling = _create_template(
        fis, role_arn, sibling_token, "sim2real experiment template without experiment options", {}
    )
    sibling_id = sibling["id"]
    ctx.on_cleanup(lambda: _delete_template(fis, sibling_id))
    assert sibling["experimentOptions"]["emptyTargetResolutionMode"] == "fail", (
        f"a template created with no experimentOptions had emptyTargetResolutionMode "
        f"{sibling['experimentOptions']['emptyTargetResolutionMode']!r}, expected 'fail'"
    )

    got_sibling = fis.get_experiment_template(id=sibling_id)["experimentTemplate"]
    assert got_sibling["experimentOptions"]["emptyTargetResolutionMode"] == "fail", (
        f"get returned sibling emptyTargetResolutionMode "
        f"{got_sibling['experimentOptions']['emptyTargetResolutionMode']!r}, expected 'fail'"
    )

    updated = fis.update_experiment_template(
        id=main_id, experimentOptions={"emptyTargetResolutionMode": "fail"}
    )["experimentTemplate"]
    assert updated["experimentOptions"]["emptyTargetResolutionMode"] == "fail", (
        f"update returned emptyTargetResolutionMode "
        f"{updated['experimentOptions']['emptyTargetResolutionMode']!r}, expected 'fail'"
    )

    got_updated = fis.get_experiment_template(id=main_id)["experimentTemplate"]
    assert got_updated["experimentOptions"]["emptyTargetResolutionMode"] == "fail", (
        f"after update, get returned emptyTargetResolutionMode "
        f"{got_updated['experimentOptions']['emptyTargetResolutionMode']!r}, expected 'fail' "
        "on the next Get"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
