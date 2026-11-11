"""get-resource-policy-absent-resource-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-resource-policy-absent-resource-not-found"
GROUP = "data-plane"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a valid resource ARN that never had a policy attached is
    ResourceNotFoundException, not an empty policy -- and the same ARN accepts and
    returns a policy once one is actually attached (positive control)."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-rg-")
    created = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))

    # (a) the specific error code, on a resource that is valid but has no attached policy
    code, message = _client_error(lambda: codebuild.get_resource_policy(resourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Resource ARN resource policy does not exist", message

    # (b) the effect is absent -- there is genuinely no policy document to retrieve,
    # confirmed by attaching one and observing the state actually change
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealControl",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["codebuild:BatchGetReportGroups"],
                "Resource": arn,
            }
        ],
    }
    codebuild.put_resource_policy(policy=json.dumps(policy_doc), resourceArn=arn)

    # (c) positive control in the same file: the same call now succeeds and returns
    # the policy that was actually attached (AWS may normalize the JSON encoding --
    # e.g. wrap singleton Action/Resource fields in lists, or reorder keys -- so
    # compare on semantic content rather than exact string/dict equality)
    resp = codebuild.get_resource_policy(resourceArn=arn)
    returned = json.loads(resp["policy"])
    assert returned["Version"] == policy_doc["Version"], (
        f"expected Version {policy_doc['Version']!r}, got {returned.get('Version')!r}"
    )
    assert len(returned["Statement"]) == 1, f"expected 1 statement, got {returned['Statement']!r}"
    returned_stmt = returned["Statement"][0]
    expected_stmt = policy_doc["Statement"][0]
    assert returned_stmt["Effect"] == expected_stmt["Effect"], (
        f"expected Effect {expected_stmt['Effect']!r}, got {returned_stmt.get('Effect')!r}"
    )
    assert _as_list(returned_stmt["Action"]) == _as_list(expected_stmt["Action"]), (
        f"expected Action {expected_stmt['Action']!r}, got {returned_stmt.get('Action')!r}"
    )
    assert _as_list(returned_stmt["Resource"]) == _as_list(expected_stmt["Resource"]), (
        f"expected Resource {expected_stmt['Resource']!r}, got {returned_stmt.get('Resource')!r}"
    )
    assert _as_list(returned_stmt["Principal"]["AWS"]) == _as_list(
        expected_stmt["Principal"]["AWS"]
    ), (
        f"expected Principal.AWS {expected_stmt['Principal']['AWS']!r}, "
        f"got {returned_stmt.get('Principal', {}).get('AWS')!r}"
    )

    # (d) delete proves gone and unusable: an independent read 404s again on the same
    # ARN that just successfully returned a policy above
    codebuild.delete_resource_policy(resourceArn=arn)
    code_after_delete, message_after_delete = _client_error(
        lambda: codebuild.get_resource_policy(resourceArn=arn)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code_after_delete!r}"
    )
    assert message_after_delete == "Resource ARN resource policy does not exist", message_after_delete


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
