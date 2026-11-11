"""batch-put-metrics-missing-iam-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-metrics-missing-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-metrics"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM role with no attached permission policy cannot call BatchPutMetrics --
    it gets AccessDeniedException, the metric it attempted to write never lands, and
    the same call from the fully-permissioned caller in the same file succeeds."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    now = int(time.time())

    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = role["Role"]["Arn"]

    # IAM has brief propagation lag for new roles/trust policies; retry the assume.
    session_name = ctx.unique_name("sim2real-behav-sess-")
    creds = _poll_until(
        lambda: _try_assume_role(sts, role_arn, session_name),
        lambda c: c is not None,
        timeout_s=45.0,
        interval_s=3.0,
        description="assuming the freshly created role",
    )

    denied_client = _client_with_creds(ctx, "sagemaker-metrics", creds)
    code, message = _error(
        lambda: denied_client.batch_put_metrics(
            TrialComponentName=tc["name"],
            MetricData=[{"MetricName": "denied-metric", "Timestamp": now, "Step": 0, "Value": 1.0}],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized to "
        f"perform: sagemaker:BatchPutMetrics on resource: arn:aws:sagemaker:{ctx.region}:{account_id}:"
        f"experiment-trial-component/{tc['name']} because no identity-based policy allows the "
        f"sagemaker:BatchPutMetrics action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same operation, same resource, with real permissions.
    control_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "allowed-metric", "Timestamp": now, "Step": 0, "Value": 9.0}],
    )
    assert not control_resp.get("Errors"), f"expected no errors, got {control_resp.get('Errors')!r}"

    # Effect absent: the denied write never created a queryable metric.
    denied_query = {
        "MetricName": "denied-metric",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    denied_result = metrics.batch_get_metrics(MetricQueries=[denied_query])["MetricQueryResults"][0]
    assert denied_result["Status"] == "Complete", f"unexpected status: {denied_result}"
    assert denied_result["MetricValues"] == [], (
        f"expected no metric values for the denied write, got {denied_result['MetricValues']!r}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _try_assume_role(sts, role_arn, session_name):
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        return resp["Credentials"]
    except ClientError:
        return None


def _client_with_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
