"""create-queue-existing-name-different-policy-not-conflicting."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-existing-name-different-policy-not-conflicting"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "create-queue-existing-name-different-policy-not-conflicting"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _policy(sqs, url):
    raw = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
    return json.loads(raw) if raw else None


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueue on an existing name ignores a Policy Sid difference (same URL, Sid not updated)
    but refuses a different Action, Resource, Principal or VisibilityTimeout (QueueAlreadyExists).
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cqpolicy-")
    base_statement = {
        "Sid": "sim2real-original", "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sqs:SendMessage", "Resource": "*",
    }
    original = {"Version": "2012-10-17", "Statement": [base_statement]}
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"VisibilityTimeout": "40", "Policy": json.dumps(original)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    stored_before = _policy(sqs, url)
    assert stored_before is not None and stored_before["Statement"][0]["Sid"] == "sim2real-original", (
        f"positive control: the originally-set Policy did not read back intact: {stored_before!r}"
    )

    sid_only = {"Version": "2012-10-17", "Statement": [{**base_statement, "Sid": "sim2real-renamed"}]}
    reissued = sqs.create_queue(
        QueueName=name,
        Attributes={"VisibilityTimeout": "40", "Policy": json.dumps(sid_only)},
        tags=_TAGS,
    )
    assert reissued["QueueUrl"] == url, (
        f"re-create with only the Sid changed returned {reissued['QueueUrl']!r}, expected the "
        f"same queue {url!r} rather than a conflict or a new queue"
    )
    stored_after_sid = _policy(sqs, url)
    assert stored_after_sid is not None and stored_after_sid["Statement"][0]["Sid"] == "sim2real-original", (
        f"a Sid-only difference must not be APPLIED either, since it was accepted as identical; "
        f"read back {stored_after_sid!r}"
    )

    for field, value, label in (
        ("Action", "sqs:GetQueueAttributes", "Action"),
        ("Resource", f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-other-queue", "Resource"),
        # Refused, so never applied.
        ("Principal", "*", "Principal"),
    ):
        different = {
            "Version": "2012-10-17",
            "Statement": [{**base_statement, field: value}],
        }
        code, msg = _err(lambda different=different: sqs.create_queue(
            QueueName=name,
            Attributes={"VisibilityTimeout": "40", "Policy": json.dumps(different)},
            tags=_TAGS,
        ))
        assert code == "QueueAlreadyExists", (
            f"re-create with a different {label} gave code {code!r}, expected QueueAlreadyExists"
        )
        assert msg == (
            "A queue already exists with the same name and a different value for attribute Policy"
        ), f"re-create with a different {label} gave message {msg!r}"
        stored = _policy(sqs, url)
        assert stored == original, (
            f"the refused {label} conflict changed the stored Policy to {stored!r}"
        )

    code, msg = _err(lambda: sqs.create_queue(
        QueueName=name, Attributes={"VisibilityTimeout": "41", "Policy": json.dumps(original)}))
    assert code == "QueueAlreadyExists", (
        f"positive control: re-create with a different VisibilityTimeout gave code {code!r}, "
        f"expected QueueAlreadyExists — the general conflict mechanism must still be active"
    )
    assert msg == (
        "A queue already exists with the same name and a different value for attribute "
        "VisibilityTimeout"
    ), f"positive control gave message {msg!r}"
    vt = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert vt["VisibilityTimeout"] == "40", (
        f"the refused VisibilityTimeout conflict changed it to {vt['VisibilityTimeout']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
