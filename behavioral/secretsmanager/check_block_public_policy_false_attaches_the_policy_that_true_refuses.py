"""block-public-policy-false-attaches-the-policy-that-true-refuses."""
from __future__ import annotations

import json
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "block-public-policy-false-attaches-the-policy-that-true-refuses"
GROUP = "representation"
SERVICES = ["secretsmanager"]

_PUBLIC_POLICY_MESSAGE = "You can not attach a resource policy that grants Public access to your secret."


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A wildcard-principal policy is refused with PublicPolicyException when BlockPublicPolicy=True
    and attached unchanged when False; a True re-put over the attached policy is still refused.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutResourcePolicy.html
    """
    sm = ctx.client("secretsmanager")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-smblockpub-")
    arn = sm.create_secret(
        Name=name,
        SecretString="guarded-value",
        Description="sim2real behavioral draft: BlockPublicPolicy True vs False",
        Tags=_sim2real_tags(),
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    # aws:Referer does not restrict who the principal is, so the grant stays broad; the per-run
    # secret keeps it unusable.
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Sim2RealBroadAllow",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:Referer": secrets.token_urlsafe(32)}},
        }],
    }
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Sim2RealScopedAllow",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }],
    }

    # Control: a scoped policy attaches with the flag on, then is cleared so the refusal below
    # starts from a secret with no policy.
    sm.put_resource_policy(
        SecretId=arn, ResourcePolicy=json.dumps(scoped_policy), BlockPublicPolicy=True
    )
    ctx.on_cleanup(lambda: _drop_policy(sm, arn))
    control = json.loads(sm.get_resource_policy(SecretId=arn)["ResourcePolicy"])
    assert control == scoped_policy, (
        f"a scoped policy must attach and read back unchanged even with BlockPublicPolicy=True; "
        f"expected {scoped_policy!r}, GetResourcePolicy returned {control!r}"
    )
    sm.delete_resource_policy(SecretId=arn)
    cleared = sm.get_resource_policy(SecretId=arn)
    assert "ResourcePolicy" not in cleared, (
        f"DeleteResourcePolicy must leave no document behind before the flag is graded; "
        f"GetResourcePolicy returned keys {sorted(cleared)!r}"
    )

    refused, refused_message = _refusal(
        lambda: sm.put_resource_policy(
            SecretId=arn, ResourcePolicy=json.dumps(public_policy), BlockPublicPolicy=True
        )
    )
    assert refused == "PublicPolicyException", (
        f"a policy whose Principal is the wildcard must be refused with PublicPolicyException when "
        f"BlockPublicPolicy=True; got {refused!r}"
    )
    assert refused_message == _PUBLIC_POLICY_MESSAGE, (
        f"unexpected PublicPolicyException message: {refused_message!r}"
    )

    after_refusal = sm.get_resource_policy(SecretId=arn)
    assert "ResourcePolicy" not in after_refusal, (
        f"the refused public policy must not have been attached; GetResourcePolicy returned "
        f"{after_refusal.get('ResourcePolicy')!r}"
    )

    sm.put_resource_policy(
        SecretId=arn, ResourcePolicy=json.dumps(public_policy), BlockPublicPolicy=False
    )
    attached = json.loads(sm.get_resource_policy(SecretId=arn)["ResourcePolicy"])
    assert attached == public_policy, (
        f"with BlockPublicPolicy=False the identical document must attach and read back with its "
        f"value preserved -- including the wildcard Principal; expected {public_policy!r}, "
        f"GetResourcePolicy returned {attached!r}"
    )
    assert attached["Statement"][0]["Principal"] == "*", (
        f"the wildcard Principal must survive as the bare string '*', not be normalised into a "
        f"structure; got {attached['Statement'][0]['Principal']!r}"
    )

    re_refused, re_refused_message = _refusal(
        lambda: sm.put_resource_policy(
            SecretId=arn, ResourcePolicy=json.dumps(public_policy), BlockPublicPolicy=True
        )
    )
    assert re_refused == "PublicPolicyException", (
        f"BlockPublicPolicy=True must refuse the broad document even when an identical one is "
        f"already attached; got {re_refused!r}"
    )
    assert re_refused_message == _PUBLIC_POLICY_MESSAGE, (
        f"unexpected PublicPolicyException message on the re-put: {re_refused_message!r}"
    )
    survivor = json.loads(sm.get_resource_policy(SecretId=arn)["ResourcePolicy"])
    assert survivor == public_policy, (
        f"the refused re-put must leave the attached document untouched; expected "
        f"{public_policy!r}, GetResourcePolicy returned {survivor!r}"
    )

    assert sm.get_secret_value(SecretId=arn)["SecretString"] == "guarded-value", (
        "the secret must remain readable to its owning account throughout the policy churn"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _drop_policy(sm, arn: str) -> None:
    """Detach the secret's resource policy, tolerating there being none."""
    try:
        sm.delete_resource_policy(SecretId=arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "InvalidRequestException"):
            raise RuntimeError(f"delete_resource_policy({arn}) -> {code}") from exc


def _refusal(fn):
    """Return the refused call's (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
