"""resource-policy-put-get-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-round-trip"
GROUP = "data-plane"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy written via PutResourcePolicy is returned unchanged by
    GetResourcePolicy, and DeleteResourcePolicy removes it so the next read reports
    ResourceNotFoundException."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-rg-")
    created = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    report_group_arn = created["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=report_group_arn, deleteReports=True))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codebuild:BatchGetReportGroups",
                "Resource": report_group_arn,
            }
        ],
    }
    policy_str = json.dumps(policy_doc)

    codebuild.put_resource_policy(resourceArn=report_group_arn, policy=policy_str)

    fetched = codebuild.get_resource_policy(resourceArn=report_group_arn)["policy"]
    fetched_doc = json.loads(fetched)

    assert fetched_doc == policy_doc, f"policy round-trip mismatch: {fetched_doc!r} != {policy_doc!r}"
    assert fetched_doc["Statement"][0]["Resource"] == report_group_arn, (
        f"round-tripped policy Resource is {fetched_doc['Statement'][0]['Resource']!r}, "
        f"expected {report_group_arn!r}"
    )

    _delete_resource_policy_when_settled(codebuild, report_group_arn)
    code, code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=report_group_arn))
    assert code == "ResourceNotFoundException", (
        f"GetResourcePolicy after delete must raise ResourceNotFoundException, got {code!r}"
    )
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"


def _delete_resource_policy_when_settled(codebuild, resource_arn, deadline_s=30.0, poll_s=2.0):
    """DeleteResourcePolicy issued right after PutResourcePolicy can race CodeBuild's
    async policy write and get InvalidInputException/InflightPolicy; retry until the
    write settles or the deadline passes."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            codebuild.delete_resource_policy(resourceArn=resource_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "InvalidInputException" and "InflightPolicy" in message and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
