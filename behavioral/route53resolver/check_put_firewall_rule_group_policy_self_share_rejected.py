"""put-firewall-rule-group-policy-self-share-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-firewall-rule-group-policy-self-share-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fresh rule group has no policy, PutFirewallRuleGroupPolicy rejects a same-account share with
    ValidationException (RSLVR-02035), and the rejection leaves no policy behind.
    """
    r53 = ctx.client("route53resolver")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]
    ctx.on_cleanup(lambda x=group["Id"]: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    arn = group["Arn"]

    pre = r53.get_firewall_rule_group_policy(Arn=arn)["FirewallRuleGroupPolicy"]
    assert json.loads(pre) == {}, f"a fresh rule group must have no policy, got {pre}"

    # RSLVR-02035 also fires for an unrelated account's principal, so it does not single out
    # self-sharing; a succeeding cross-account share would need a second, RAM-linked account.
    self_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},'
        f'"Action":"route53resolver:GetFirewallRuleGroup","Resource":"{arn}"}}]}}'
    )
    code, message = _error(
        lambda: r53.put_firewall_rule_group_policy(
            Arn=arn, FirewallRuleGroupPolicy=self_policy
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a same-account share policy, got {code}"
    )
    expected = (
        f'[RSLVR-02035] The specified IAM policy isn\'t valid: "{self_policy}". Provide a valid '
        "policy that allows a DNS Firewall rule group to be shared with another AWS account."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    post = r53.get_firewall_rule_group_policy(Arn=arn)["FirewallRuleGroupPolicy"]
    assert json.loads(post) == {}, f"a rejected self-share must not persist a policy, got {post}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
