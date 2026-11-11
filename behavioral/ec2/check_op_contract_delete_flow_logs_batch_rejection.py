"""op-contract-delete-flow-logs-batch-rejection."""
from __future__ import annotations

CHECK = "op-contract-delete-flow-logs-batch-rejection"
GROUP = "error-semantics"
SERVICES = ["ec2"]

import json
import time

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFlowLogs deletes a lone valid id, but any unknown id rejects the whole batch with
    InvalidFlowLogId.NotFound naming only the unknown ids and deleting nothing; DryRun returns
    DryRunOperation."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    bogus_ids = ["fl-00000000000000000", "fl-11111111111111111"]

    vpc_id = _get_or_create_vpc(ctx, ec2)

    log_group_name = ctx.unique_name("/sim2real-behav/flowlogs-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"sim2real-behav-check": CHECK}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    role_name = ctx.unique_name("sim2real-behav-flowlogs-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    # Positive control: shows the rejections below are specific to unknown ids.
    flow_log_id_1 = _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name)
    ctx.on_cleanup(lambda: _cleanup_flow_log(ec2, flow_log_id_1))

    resp = ec2.delete_flow_logs(FlowLogIds=[flow_log_id_1])
    assert resp.get("Unsuccessful", []) == [], f"expected no failures, got {resp.get('Unsuccessful')!r}"
    remaining = ec2.describe_flow_logs(FlowLogIds=[flow_log_id_1])["FlowLogs"]
    assert remaining == [], f"expected {flow_log_id_1!r} to be gone after delete, got {remaining!r}"

    try:
        ec2.delete_flow_logs(FlowLogIds=bogus_ids)
        raise AssertionError("expected DeleteFlowLogs to be rejected when every flow log id is unknown")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == "InvalidFlowLogId.NotFound", f"unexpected error code {code!r}"
        assert message == (
            f"These flow log ids in the input list are not found: [TotalCount: {len(bogus_ids)}] {' '.join(bogus_ids)}"
        ), message

    # No per-item "Unsuccessful" path: a valid id alongside a bogus one is rejected and survives.
    flow_log_id_2 = _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name)
    ctx.on_cleanup(lambda: _cleanup_flow_log(ec2, flow_log_id_2))

    try:
        ec2.delete_flow_logs(FlowLogIds=[flow_log_id_2, bogus_ids[0]])
        raise AssertionError(
            "expected DeleteFlowLogs to reject the whole batch when it contains any unknown id, "
            "even alongside an otherwise-valid id"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == "InvalidFlowLogId.NotFound", f"unexpected error code {code!r}"
        assert message == f"These flow log ids in the input list are not found: [TotalCount: 1] {bogus_ids[0]}", message

    survived = ec2.describe_flow_logs(FlowLogIds=[flow_log_id_2])["FlowLogs"]
    assert len(survived) == 1 and survived[0]["FlowLogId"] == flow_log_id_2, (
        f"expected {flow_log_id_2!r} to survive the rejected mixed batch (no partial delivery), "
        f"got {survived!r}"
    )

    dry_run_code, dry_run_message = _error(lambda: ec2.delete_flow_logs(FlowLogIds=[bogus_ids[0]], DryRun=True))
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", dry_run_message


def _get_or_create_vpc(ctx, ec2):
    from botocore.exceptions import ClientError

    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.213.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
                }
            ],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
        return vpc_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VpcLimitExceeded":
            raise

    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    if not vpcs:
        raise AssertionError("VPC quota exhausted and no existing VPC available to reuse")
    default = [v for v in vpcs if v.get("IsDefault")]
    return (default[0] if default else vpcs[0])["VpcId"]


def _retry_create_flow_log(ec2, vpc_id, role_arn, log_group_name, timeout_s=90.0, interval_s=5.0):
    """CreateFlowLogs needs the flow-log role's trust to have propagated; retry briefly."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.create_flow_logs(
                ResourceType="VPC",
                ResourceIds=[vpc_id],
                TrafficType="ALL",
                LogDestinationType="cloud-watch-logs",
                LogGroupName=log_group_name,
                DeliverLogsPermissionArn=role_arn,
                TagSpecifications=[
                    {
                        "ResourceType": "vpc-flow-log",
                        "Tags": [{"Key": "sim2real-behav-check", "Value": CHECK}],
                    }
                ],
            )
            if resp.get("Unsuccessful"):
                last_error = resp["Unsuccessful"][0]["Error"]["Message"]
                time.sleep(interval_s)
                continue
            return resp["FlowLogIds"][0]
        except Exception as exc:  # noqa: BLE001 - IAM propagation surfaces as ClientError variants
            last_error = str(exc)
            time.sleep(interval_s)
    raise AssertionError(f"CreateFlowLogs never succeeded (IAM propagation?): {last_error}")


def _cleanup_flow_log(ec2, flow_log_id):
    from botocore.exceptions import ClientError

    try:
        ec2.delete_flow_logs(FlowLogIds=[flow_log_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidFlowLogId.NotFound":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
