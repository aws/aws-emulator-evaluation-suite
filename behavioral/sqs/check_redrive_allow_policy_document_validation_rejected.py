"""redrive-allow-policy-document-validation-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-allow-policy-document-validation-rejected"
GROUP = 'dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "redrive-allow-policy-document-validation-rejected"}
_PREFIX = "Amazon SQS can't create the redrive allow policy."


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _rap(sqs, url):
    raw = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["RedriveAllowPolicy"]).get("Attributes", {}).get(
        "RedriveAllowPolicy")
    return json.loads(raw) if raw else None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes refuses a RedriveAllowPolicy whose byQueue lists 11 or no source ARNs,
    whose allowAll carries source ARNs, or whose redrivePermission is unknown, and each
    refusal leaves the stored 10-ARN byQueue policy exactly as accepted."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-rap-")
    dlq_url = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    arn_root = dlq_arn.rsplit(":", 1)[0]
    sources = [f"{arn_root}:{base}-s{i}" for i in range(11)]

    good = {"redrivePermission": "byQueue", "sourceQueueArns": sources[:10]}
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": json.dumps(good)})
    stored = _rap(sqs, dlq_url)
    assert stored == good, (
        f"positive control: the 10-ARN byQueue policy read back as permission "
        f"{(stored or {}).get('redrivePermission')!r} with "
        f"{len((stored or {}).get('sourceQueueArns', []))} ARNs"
    )

    cases = [
        ({"redrivePermission": "byQueue", "sourceQueueArns": sources},
         "The maximum number of source queue ARNs you can specify is 10."),
        ({"redrivePermission": "byQueue"},
         "When you specify the byQueue permission type, you must also specify one or more "
         "sourceQueueArns values."),
        ({"redrivePermission": "allowAll", "sourceQueueArns": sources[:1]},
         "To specify one or more source queue ARNs, you must set redrivePermission to byQueue."),
    ]
    for doc, reason in cases:
        text = json.dumps(doc)
        code, msg = _err(lambda t=text: sqs.set_queue_attributes(
            QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": t}))
        label = f"{doc['redrivePermission']} with {len(doc.get('sourceQueueArns', []))} ARNs"
        assert code == "InvalidParameterValue", f"{label} gave code {code!r}"
        assert msg == (f"Value {text} for parameter RedriveAllowPolicy is invalid. Reason: "
                       f"{_PREFIX} {reason}"), f"{label} gave message {msg!r}"
        after = _rap(sqs, dlq_url)
        assert after == good, (
            f"the refused {label} policy changed the stored one: now permission "
            f"{(after or {}).get('redrivePermission')!r} with "
            f"{len((after or {}).get('sourceQueueArns', []))} ARNs"
        )

    code, msg = _err(lambda: sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={
        "RedriveAllowPolicy": json.dumps({"redrivePermission": "sometimes"})}))
    assert code == "InvalidAttributeValue", f"an unknown redrivePermission gave code {code!r}"
    assert msg == ("Invalid value for the parameter RedriveAllowPolicy. Reason: Amazon SQS can't "
                   "create the redrive allow policy, as it’s in an unsupported format."), (
        f"an unknown redrivePermission gave message {msg!r}"
    )
    assert _rap(sqs, dlq_url) == good, "the refused unknown-permission policy changed the stored one"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
