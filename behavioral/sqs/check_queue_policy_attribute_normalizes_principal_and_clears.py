"""queue-policy-attribute-normalizes-principal-and-clears."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "queue-policy-attribute-normalizes-principal-and-clears"
GROUP = 'permissions'
SERVICES = ['sqs']

_TAGS = {"sim2real": "queue-policy-attribute-normalizes-principal-and-clears"}


def _policy(sqs, url):
    raw = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
    return json.loads(raw) if raw else None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stored queue policy reads back with a bare account-id principal normalized to the root ARN;
    setting Policy to "" removes the attribute, and a later AddPermission builds a fresh policy
    holding only its own statement.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-qpol-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    root = f"arn:aws:iam::{ctx.account}:root"

    written = {"Version": "2012-10-17", "Statement": [{
        "Sid": "sim2real-send", "Effect": "Allow", "Principal": {"AWS": ctx.account},
        "Action": "sqs:SendMessage", "Resource": arn}]}
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(written)})
    stored = _policy(sqs, url)
    assert stored is not None, "the written Policy did not read back"
    assert stored.get("Version") == "2012-10-17", f"Version read back as {stored.get('Version')!r}"
    stmts = stored.get("Statement", [])
    assert len(stmts) == 1, f"the stored policy has {len(stmts)} statements, expected 1"
    st = stmts[0]
    assert (st.get("Sid"), st.get("Effect"), st.get("Action")) == (
        "sim2real-send", "Allow", "sqs:SendMessage"), (
        f"the statement read back as Sid={st.get('Sid')!r} Effect={st.get('Effect')!r} "
        f"Action={st.get('Action')!r}"
    )
    assert st.get("Resource") == arn, "the statement's Resource is not the queue ARN"
    principal = st.get("Principal", {}).get("AWS")
    assert principal == root, (
        f"a bare account-id principal must read back as the account root ARN; got a "
        f"{'bare account id' if principal == ctx.account else 'different value'} "
        f"of length {len(str(principal))}"
    )

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {})
    assert "Policy" not in attrs, (
        f"after setting Policy to '' the attribute still reads {attrs.get('Policy')!r}"
    )

    label = ctx.unique_name("sim2real-perm")
    sqs.add_permission(
        QueueUrl=url, Label=label, AWSAccountIds=[ctx.account], Actions=["ReceiveMessage"])
    rebuilt = _policy(sqs, url)
    assert rebuilt is not None, "AddPermission on a cleared queue produced no Policy"
    sids = [s.get("Sid") for s in rebuilt.get("Statement", [])]
    assert sids == [label], (
        f"after clear + AddPermission the policy holds {len(sids)} statements; "
        f"cleared statement {'resurrected' if 'sim2real-send' in sids else 'absent'}, "
        f"new label {'present' if label in sids else 'absent'}"
    )
    action = rebuilt["Statement"][0].get("Action")
    assert action == "SQS:ReceiveMessage", (
        f"AddPermission's statement carries Action {action!r}, expected 'SQS:ReceiveMessage'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
