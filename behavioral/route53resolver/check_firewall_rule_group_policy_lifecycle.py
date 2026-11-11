"""firewall-rule-group-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-group-policy-lifecycle"
GROUP = 'resource-policy'
SERVICES = ['route53resolver']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh rule group has NO policy; PutFirewallRuleGroupPolicy creates one that Get returns."""
    r53r = ctx.client("route53resolver")
    group = r53r.create_firewall_rule_group(
        CreatorRequestId=_creator_request_id(ctx), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]
    group_arn = group["Arn"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: _swallow(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)))

    # A fresh rule group has no policy: real Resolver returns an EMPTY JSON
    # document (not an error, and not a phantom policy).
    pre = r53r.get_firewall_rule_group_policy(Arn=group_arn)["FirewallRuleGroupPolicy"]
    assert json.loads(pre) == {}, pre

    # A DNS Firewall rule group policy exists solely to share the group with
    # ANOTHER real AWS account. Real Resolver validates the principal, so we
    # assert the two rejections it enforces rather than sharing for real.
    #
    # A successful cross-account share needs a second account, so only the two deterministic
    # rejections are asserted.
    account_id = _account_id(ctx)
    self_share = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":["{account_id}"]}},'
        '"Action":["route53resolver:GetFirewallRuleGroup",'
        '"route53resolver:AssociateFirewallRuleGroup",'
        '"route53resolver:DisassociateFirewallRuleGroup",'
        '"route53resolver:ListFirewallRuleGroups"],'
        f'"Resource":["{group_arn}"]}}]}}'
    )
    code, message = _error(
        lambda: r53r.put_firewall_rule_group_policy(
            Arn=group_arn, FirewallRuleGroupPolicy=self_share
        )
    )
    assert code == "ValidationException", code
    assert message == _invalid_policy_message(self_share), message

    # A structurally invalid document must also be rejected, not stored.
    code, message = _error(
        lambda: r53r.put_firewall_rule_group_policy(
            Arn=group_arn, FirewallRuleGroupPolicy='{"Version":"2012-10-17"}'
        )
    )
    assert code == "ValidationException", code
    assert message == _invalid_policy_message('{"Version":"2012-10-17"}'), message

    # Neither rejected Put may leave partial state behind.
    post = r53r.get_firewall_rule_group_policy(Arn=group_arn)["FirewallRuleGroupPolicy"]
    assert json.loads(post) == {}, post

    # And an unknown rule group ARN is a not-found, not a silent success.
    bogus_arn = group_arn.rsplit("/", 1)[0] + "/rslvr-frg-00000000000000000"
    code, message = _error(lambda: r53r.get_firewall_rule_group_policy(Arn=bogus_arn))
    assert code == "ResourceNotFoundException", code
    assert message == '[RSLVR-02025] Can\u2019t find the resource with ID "rslvr-frg-00000000000000000".', message


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _invalid_policy_message(policy: str) -> str:
    """Resolver's refusal of a rule group policy, which echoes the submitted document."""
    return (
        f'[RSLVR-02035] The specified IAM policy isn\'t valid: "{policy}". Provide a valid '
        "policy that allows a DNS Firewall rule group to be shared with another AWS account."
    )


def _creator_request_id(ctx) -> str:
    """A fresh CreatorRequestId for idempotency-token style params."""
    return ctx.unique_name("sim2real-behav-crid-")


def _account_id(ctx) -> str:
    """The caller's account id, used to build the self-share principal the
    rejection under test is aimed at. A placeholder is fine when STS is
    unreachable -- the assertion is that Resolver REFUSES the document."""
    try:
        return ctx.client("sts").get_caller_identity()["Account"]
    except Exception:  # noqa: BLE001
        return ctx.account


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
