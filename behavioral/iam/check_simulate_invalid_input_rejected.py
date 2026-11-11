"""simulate-invalid-input-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "simulate-invalid-input-rejected"
GROUP = 'errors'
SERVICES = ['iam']

VALID_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)
BUCKET_ARN = "arn:aws:s3:::sim2real-behav-simulated-bucket"


def _err(fn):
    """Call fn(); return the botocore Error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _control_decision(iam):
    """The known-good simulation: the policy allows s3:ListBucket on the bucket ARN."""
    results = iam.simulate_custom_policy(
        PolicyInputList=[VALID_POLICY],
        ActionNames=["s3:ListBucket"],
        ResourceArns=[BUCKET_ARN],
    )["EvaluationResults"]
    assert len(results) == 1, f"expected one EvaluationResult, got {results}"
    return results[0]["EvalDecision"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The simulation APIs reject malformed input: an unparseable policy document and a non-ARN
    ResourceArns value are InvalidInput, a nonexistent PolicySourceArn is NoSuchEntity, each with
    its exact message; a good simulation stays 'allowed'."""
    iam = ctx.client("iam")

    # --- Control before: the valid call works, so any error below is attributable to the one
    # thing that was broken.
    assert _control_decision(iam) == "allowed", (
        "baseline: the valid policy must allow s3:ListBucket on the bucket ARN, got "
        f"{_control_decision(iam)!r}"
    )

    # --- Break exactly one thing: an unparseable policy document in PolicyInputList.
    code_doc, msg_doc = _err(
        lambda: iam.simulate_custom_policy(
            PolicyInputList=["{not valid json"],
            ActionNames=["s3:ListBucket"],
            ResourceArns=[BUCKET_ARN],
        )
    )
    assert code_doc == "InvalidInput", (
        f"an unparseable PolicyInputList entry must be rejected InvalidInput, got {code_doc!r}"
    )
    want = "Policy input list item 1 has invalid content"
    assert msg_doc == want, f"InvalidInput message: wanted {want!r}, got {msg_doc!r}"
    assert _control_decision(iam) == "allowed", (
        "the rejected simulation must leave the simulator working: the control call must still "
        "return 'allowed'"
    )

    # --- Break exactly one thing: a ResourceArns entry that is not an ARN.
    code_arn, msg_arn = _err(
        lambda: iam.simulate_custom_policy(
            PolicyInputList=[VALID_POLICY],
            ActionNames=["s3:ListBucket"],
            ResourceArns=["not-an-arn"],
        )
    )
    assert code_arn == "InvalidInput", (
        f"a non-ARN ResourceArns entry must be rejected InvalidInput, got {code_arn!r}"
    )
    want = "ResourceNames are not in a valid ARN format: not-an-arn."
    assert msg_arn == want, f"InvalidInput message: wanted {want!r}, got {msg_arn!r}"
    assert _control_decision(iam) == "allowed", (
        "the rejected simulation must leave the simulator working: the control call must still "
        "return 'allowed'"
    )

    # --- Break exactly one thing: SimulatePrincipalPolicy against a principal that does not exist.
    account = ctx.client("sts").get_caller_identity()["Account"]
    ghost_arn = f"arn:aws:iam::{account}:user/{ctx.unique_name('sim2real-behav-ghost-')}"
    code_principal, msg_principal = _err(
        lambda: iam.simulate_principal_policy(
            PolicySourceArn=ghost_arn, ActionNames=["s3:ListBucket"]
        )
    )
    assert code_principal == "NoSuchEntity", (
        "SimulatePrincipalPolicy for a nonexistent principal must be NoSuchEntity, never an "
        f"implicitDeny result for a phantom identity; got {code_principal!r}"
    )
    want = "Unable to retrieve specified IAM entity."
    assert msg_principal == want, f"NoSuchEntity message: wanted {want!r}, got {msg_principal!r}"

    # --- Effect absent: the ghost principal was not created as a side effect of simulating it.
    ghost_name = ghost_arn.rsplit("/", 1)[1]
    code_ghost, msg_ghost = _err(lambda: iam.get_user(UserName=ghost_name))
    assert code_ghost == "NoSuchEntity", (
        "the rejected simulation must not have created the principal it named; GetUser returned "
        f"{code_ghost!r}"
    )
    want = f"The user with name {ghost_name} cannot be found."
    assert msg_ghost == want, f"NoSuchEntity message: wanted {want!r}, got {msg_ghost!r}"

    # --- Control after: a real principal simulates fine, proving SimulatePrincipalPolicy itself is
    # functional and the NoSuchEntity above was about the missing entity.
    real_user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=real_user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=real_user))
    real_arn = iam.get_user(UserName=real_user)["User"]["Arn"]
    real_results = iam.simulate_principal_policy(
        PolicySourceArn=real_arn, ActionNames=["s3:ListBucket"]
    )["EvaluationResults"]
    assert len(real_results) == 1, f"expected one EvaluationResult, got {real_results}"
    assert real_results[0]["EvalDecision"] == "implicitDeny", (
        "a real user with no permissions must simulate to implicitDeny (not an error, and not "
        f"'allowed'); got {real_results[0]['EvalDecision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
