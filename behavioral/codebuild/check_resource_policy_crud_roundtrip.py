"""resource-policy-crud-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-crud-roundtrip"
GROUP = "data-plane"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a report group persists a policy that GetResourcePolicy
    returns content-identical, and DeleteResourcePolicy removes it entirely."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-rg-")
    created = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    arn = created["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBatchGetReportGroups",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codebuild:BatchGetReportGroups",
                "Resource": arn,
            }
        ],
    }
    policy_str = json.dumps(policy_doc)

    codebuild.put_resource_policy(resourceArn=arn, policy=policy_str)

    fetched = codebuild.get_resource_policy(resourceArn=arn)
    returned_doc = json.loads(fetched["policy"])
    # Compare parsed documents (services may re-serialize JSON whitespace/order on
    # storage) rather than raw bytes -- this still catches any content drift.
    assert returned_doc == policy_doc, f"policy content mismatch: {returned_doc} != {policy_doc}"

    _delete_policy_when_settled(codebuild, arn)

    code, code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"


def _delete_policy_when_settled(codebuild, resource_arn, deadline_s=30.0, poll_s=2.0) -> None:
    """DeleteResourcePolicy right after PutResourcePolicy can race CodeBuild's async policy
    write (InvalidInputException / InflightPolicy); retry until the write settles, and raise
    on the deadline."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            codebuild.delete_resource_policy(resourceArn=resource_arn)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            inflight = err.get("Code") == "InvalidInputException" and "InflightPolicy" in err.get("Message", "")
            if inflight and time.monotonic() < deadline:
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
