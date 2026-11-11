"""get-queue-url-does-not-format-validate-the-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-queue-url-does-not-format-validate-the-name"
GROUP = "errors"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"
_GONE_MSG = "The specified queue does not exist."
_BAD_FORMAT = "InvalidParameterValue"
_MSG_NAME = "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"


def _error(fn):
    """The botocore Error dict ``fn()`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetQueueUrl does not format-validate names: a malformed name gets NonExistentQueue.

    CreateQueue refuses the same string with InvalidParameterValue; an existing name resolves.
    """
    sqs = ctx.client("sqs")

    ok_name = ctx.unique_name("sim2real-behav-gquf-")
    ok_url = sqs.create_queue(
        QueueName=ok_name, tags={"sim2real": "get-queue-url-does-not-format-validate-the-name"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=ok_url))
    resolved = sqs.get_queue_url(QueueName=ok_name)["QueueUrl"]
    assert resolved == ok_url, f"positive control: GetQueueUrl({ok_name!r}) returned {resolved!r}, expected {ok_url!r}"

    malformed = ctx.unique_name("sim2real-behav-gquf-bad!") + "!"
    err_create = _error(lambda: sqs.create_queue(QueueName=malformed))
    assert err_create.get("Code") == _BAD_FORMAT, (
        f"CreateQueue({malformed!r}) (illegal character) gave {err_create!r}, "
        f"expected the positive control {_BAD_FORMAT!r} — this check needs CreateQueue to "
        f"validate the string it reuses against GetQueueUrl below"
    )
    assert err_create.get("Message") == _MSG_NAME, f"got {err_create!r}"

    err_malformed = _error(lambda: sqs.get_queue_url(QueueName=malformed))
    assert err_malformed.get("Code") == _GONE, (
        f"GetQueueUrl({malformed!r}) (illegal character, never created) gave {err_malformed!r}, "
        f"expected {_GONE!r} — the same code a well-formed absent name gets, not CreateQueue's "
        f"{_BAD_FORMAT!r}"
    )
    assert err_malformed.get("Message") == _GONE_MSG, f"got {err_malformed!r}"

    never_created = ctx.unique_name("sim2real-behav-gquf-absent-")
    err_absent = _error(lambda: sqs.get_queue_url(QueueName=never_created))
    assert err_absent.get("Code") == _GONE, (
        f"GetQueueUrl({never_created!r}) (well-formed, never created) gave {err_absent!r}, "
        f"expected {_GONE!r}"
    )
    assert err_absent.get("Message") == _GONE_MSG, f"got {err_absent!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
