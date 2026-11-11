"""register-event-topic-absent-directory-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-event-topic-absent-directory-rejected"
GROUP = 'event-topics'
SERVICES = ['ds']
# Also calls sns to create the (free) topic that the ds calls point at.

# TopicName pattern is ^[a-zA-Z0-9_-]+$, so a dot is a validation failure regardless of whether
# the directory or the topic exists.
_ILLEGAL_TOPIC_NAME = "sim2real.behav.topic"


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise.
    ds echoes the refused call's RequestId in its message, so the caller needs it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_directory_id() -> str:
    """A DirectoryId that satisfies the modeled pattern ^d-[0-9a-f]{10}$ but names nothing."""
    return "d-" + uuid.uuid4().hex[:10]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Register/Deregister/DescribeEventTopics on an absent DirectoryId raise EntityDoesNotExistException
    (not an empty list), an illegal TopicName gets ValidationException, and the SNS topic is untouched.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_RegisterEventTopic.html"""
    ds = ctx.client("ds")
    sns = ctx.client("sns")
    absent = _absent_directory_id()

    topic_name = ctx.unique_name("sim2real-behav-").replace(".", "-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    before = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]

    # Control: the account-scoped read is a legitimate success and our topic is not in it.
    unfiltered = ds.describe_event_topics()
    assert isinstance(unfiltered.get("EventTopics"), list), (
        f"unfiltered DescribeEventTopics must return an EventTopics list, got {unfiltered}"
    )
    assert topic_name not in {t.get("TopicName") for t in unfiltered["EventTopics"]}, (
        f"{topic_name} is registered before we registered it"
    )

    # Break exactly one thing: the DirectoryId does not exist.
    not_found = f"Directory: '{absent}' does not exist."
    registered, registered_message, registered_request = _client_error(
        lambda: ds.register_event_topic(DirectoryId=absent, TopicName=topic_name)
    )
    assert registered == "EntityDoesNotExistException", (
        f"RegisterEventTopic(DirectoryId={absent}) must raise EntityDoesNotExistException (the "
        f"only not-found error its shape declares), got {registered}"
    )
    expected = f"{not_found} : RequestId: {registered_request}"
    assert registered_message == expected, (
        f"RegisterEventTopic must refuse with {expected!r}, got {registered_message!r}"
    )

    scoped, scoped_message, scoped_request = _client_error(
        lambda: ds.describe_event_topics(DirectoryId=absent)
    )
    assert scoped == "EntityDoesNotExistException", (
        f"DescribeEventTopics(DirectoryId={absent}) must raise EntityDoesNotExistException, got "
        f"{scoped} — an empty EventTopics list here is exactly the failure mode the existing "
        f"empty-account golden cannot detect"
    )
    expected = f"{not_found} : RequestId: {scoped_request}"
    assert scoped_message == expected, (
        f"DescribeEventTopics must refuse with {expected!r}, got {scoped_message!r}"
    )

    deregistered, deregistered_message, deregistered_request = _client_error(
        lambda: ds.deregister_event_topic(DirectoryId=absent, TopicName=topic_name)
    )
    assert deregistered == "EntityDoesNotExistException", (
        f"DeregisterEventTopic(DirectoryId={absent}) must raise EntityDoesNotExistException, got "
        f"{deregistered}"
    )
    expected = f"{not_found} : RequestId: {deregistered_request}"
    assert deregistered_message == expected, (
        f"DeregisterEventTopic must refuse with {expected!r}, got {deregistered_message!r}"
    )

    # An illegal TopicName is refused earlier, by validation, and with a different code.
    bad_name, bad_name_message, _bad_name_request = _client_error(
        lambda: ds.register_event_topic(DirectoryId=absent, TopicName=_ILLEGAL_TOPIC_NAME)
    )
    assert bad_name == "ValidationException", (
        f"RegisterEventTopic(TopicName={_ILLEGAL_TOPIC_NAME!r}) must be refused with "
        f"ValidationException — the TopicName pattern is ^[a-zA-Z0-9_-]+$ — got {bad_name}"
    )
    expected = (
        f"1 validation error detected: Value '{_ILLEGAL_TOPIC_NAME}' at 'topicName' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_-]+"
    )
    assert bad_name_message == expected, (
        f"RegisterEventTopic must refuse the illegal name with {expected!r}, got {bad_name_message!r}"
    )
    assert bad_name != registered, (
        f"an illegal TopicName and an absent directory must not share one code ({registered!r})"
    )

    # Effect absent, part 1: nothing was registered account-wide.
    after_topics = ds.describe_event_topics()["EventTopics"]
    assert topic_name not in {t.get("TopicName") for t in after_topics}, (
        f"{topic_name} appears in DescribeEventTopics after a REFUSED RegisterEventTopic: "
        f"{after_topics}"
    )

    # The operator grants SNS publish rights, so ds never rewrites the topic policy itself.
    after = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert after.get("Policy") == before.get("Policy"), (
        f"a refused RegisterEventTopic rewrote the topic policy: {before.get('Policy')!r} -> "
        f"{after.get('Policy')!r} — ds never grants itself publish rights"
    )
    assert "directoryservice" not in json.dumps(after.get("Policy") or "{}").lower(), (
        f"a refused RegisterEventTopic added a Directory Service statement to the topic policy: "
        f"{after.get('Policy')!r}"
    )
    assert after.get("SubscriptionsConfirmed") == before.get("SubscriptionsConfirmed"), (
        f"a refused RegisterEventTopic changed the topic's subscription count: "
        f"{before.get('SubscriptionsConfirmed')} -> {after.get('SubscriptionsConfirmed')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
