"""resource-policy-roundtrip-report-group."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "resource-policy-roundtrip-report-group"
GROUP = "data-plane"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy/GetResourcePolicy/DeleteResourcePolicy round-trip on a report group ARN."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-rg-")
    created = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": "true"}],
    )["reportGroup"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "codebuild:BatchGetReportGroups",
                    "codebuild:ListReportsForReportGroup",
                ],
                "Resource": arn,
            }
        ],
    }
    policy_str = json.dumps(policy_doc)

    put_resp = codebuild.put_resource_policy(policy=policy_str, resourceArn=arn)
    assert put_resp["resourceArn"] == arn, f"PutResourcePolicy echoed {put_resp['resourceArn']!r}, expected {arn!r}"

    get_resp = codebuild.get_resource_policy(resourceArn=arn)
    round_tripped = json.loads(get_resp["policy"])
    assert round_tripped == policy_doc, f"policy mismatch: {round_tripped} != {policy_doc}"

    codebuild.delete_resource_policy(resourceArn=arn)

    code, code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"

    # DeleteResourcePolicy on an already-absent policy is idempotent (real AWS returns 200,
    # not ResourceNotFoundException).
    codebuild.delete_resource_policy(resourceArn=arn)

    # The identifier is reusable: PutResourcePolicy on the same report group ARN after the
    # delete succeeds and round-trips again, rather than staying wedged.
    ctx.on_cleanup(lambda: codebuild.delete_resource_policy(resourceArn=arn))
    codebuild.put_resource_policy(policy=policy_str, resourceArn=arn)
    reattached = json.loads(codebuild.get_resource_policy(resourceArn=arn)["policy"])
    assert reattached == policy_doc, f"reattached policy mismatch: {reattached} != {policy_doc}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
