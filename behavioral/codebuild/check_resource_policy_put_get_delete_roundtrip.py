"""resource-policy-put-get-delete-roundtrip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

def _client_error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_report_group(cb, ctx):
    """A uniquely-named, tagged TEST report group, with teardown registered."""
    rg = cb.create_report_group(
        name=ctx.unique_name("sim2real-behav-rg-"),
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))
    return rg


CHECK = "resource-policy-put-get-delete-roundtrip"
GROUP = 'lifecycle'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put/Get/DeleteResourcePolicy round-trip on a report group; a malformed document is
    refused without overwriting the stored policy, and after delete Get is ResourceNotFound.
    """
    cb = ctx.client("codebuild")
    rg = _create_report_group(cb, ctx)
    arn = rg["arn"]
    account = arn.split(":")[4]
    action = "codebuild:BatchGetReportGroups"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": [action],
            "Resource": arn,
        }],
    })

    put = cb.put_resource_policy(policy=policy, resourceArn=arn)
    ctx.on_cleanup(lambda: cb.delete_resource_policy(resourceArn=arn))
    assert put.get("resourceArn") == arn, put

    got = json.loads(cb.get_resource_policy(resourceArn=arn)["policy"])
    stmts = got.get("Statement", [])
    assert len(stmts) == 1, got
    assert stmts[0]["Effect"] == "Allow", got
    stored_actions = stmts[0]["Action"]
    stored_actions = [stored_actions] if isinstance(stored_actions, str) else stored_actions
    assert action in stored_actions, got

    # A refused write must not replace the stored policy.
    code, code_msg = _client_error(lambda: cb.put_resource_policy(policy="{ not json", resourceArn=arn))
    assert code == "InvalidInputException", (
        f"PutResourcePolicy must reject a non-JSON policy document, got {code!r}"
    )
    assert code_msg == "Problem parsing given policy", f"unexpected message: {code_msg!r}"
    after = json.loads(cb.get_resource_policy(resourceArn=arn)["policy"])
    assert after == got, (
        f"the rejected PutResourcePolicy clobbered the stored policy: {after} != {got}"
    )

    cb.delete_resource_policy(resourceArn=arn)
    code, code_msg = _client_error(lambda: cb.get_resource_policy(resourceArn=arn))
    assert code == "ResourceNotFoundException", (
        f"GetResourcePolicy after delete must raise ResourceNotFoundException, got {code!r}"
    )
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"

    # Control: the report group itself survived the policy lifecycle.
    live = cb.batch_get_report_groups(reportGroupArns=[arn])
    assert len(live.get("reportGroups", [])) == 1, live
    assert live["reportGroups"][0]["status"] == "ACTIVE", live


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
