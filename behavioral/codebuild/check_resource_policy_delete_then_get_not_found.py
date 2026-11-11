"""resource-policy-delete-then-get-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-delete-then-get-not-found"
GROUP = "data-plane"
SERVICES = ["codebuild"]


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy removes the policy; GetResourcePolicy then 404s, while an
    untouched sibling resource's policy is still readable (in-file positive control)."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:root"

    def _make_report_group(suffix: str) -> str:
        name = ctx.unique_name(f"sim2real-behav-rg-{suffix}-")
        created = codebuild.create_report_group(
            name=name,
            type="TEST",
            exportConfig={"exportConfigType": "NO_EXPORT"},
            tags=[{"key": "sim2real", "value": CHECK}],
        )
        arn = created["reportGroup"]["arn"]
        ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))
        return arn

    def _policy_for(arn: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowDescribe",
                        "Effect": "Allow",
                        "Principal": {"AWS": principal},
                        "Action": "codebuild:BatchGetReportGroups",
                        "Resource": arn,
                    }
                ],
            }
        )

    # Resource A: policy is attached, confirmed present, then deleted.
    arn_a = _make_report_group("a")
    codebuild.put_resource_policy(resourceArn=arn_a, policy=_policy_for(arn_a))

    attached = codebuild.get_resource_policy(resourceArn=arn_a)["policy"]
    assert json.loads(attached) == json.loads(_policy_for(arn_a)), (
        f"policy must actually be attached before the delete under test: {attached}"
    )

    codebuild.delete_resource_policy(resourceArn=arn_a)

    code, code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=arn_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"

    # Resource B: positive control, untouched sibling still has its policy.
    arn_b = _make_report_group("b")
    codebuild.put_resource_policy(resourceArn=arn_b, policy=_policy_for(arn_b))
    ctx.on_cleanup(lambda: codebuild.delete_resource_policy(resourceArn=arn_b))

    control = codebuild.get_resource_policy(resourceArn=arn_b)["policy"]
    assert json.loads(control) == json.loads(_policy_for(arn_b)), (
        f"untouched sibling resource's policy must remain readable and unchanged: {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
