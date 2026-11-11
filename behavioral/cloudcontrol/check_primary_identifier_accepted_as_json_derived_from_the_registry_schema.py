"""primary-identifier-accepted-as-json-derived-from-the-registry-schema."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "primary-identifier-accepted-as-json-derived-from-the-registry-schema"
GROUP = "lifecycle"
SERVICES = ["cloudcontrol"]

QUEUE_TYPE = "AWS::SQS::Queue"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
VISIBILITY = 30


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c5",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetResource accepts the registry schema's primary identifier as a string or as JSON with
    identical results, and refuses a JSON identifier naming a non-identifier property.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_GetResource.html
    """
    cc = ctx.client("cloudcontrol")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    # The identifier property is read from the type's registry schema, not hard-coded.
    schema = json.loads(cfn.describe_type(Type="RESOURCE", TypeName=QUEUE_TYPE)["Schema"])
    pointers = schema["primaryIdentifier"]
    assert len(pointers) == 1, (
        f"the registry reports primaryIdentifier {pointers!r} for {QUEUE_TYPE}; this check derives "
        f"a single-property JSON identifier and needs exactly one segment"
    )
    id_property = pointers[0].rsplit("/", 1)[-1]
    assert id_property in schema["properties"], (
        f"the registry declares primaryIdentifier {pointers[0]!r} for {QUEUE_TYPE} but "
        f"{id_property!r} is not among its declared properties "
        f"{sorted(schema['properties'])}; the schema is not self-consistent"
    )

    queue_name = ctx.unique_name("sim2real-behav-ccjsonid-")
    created = cc.create_resource(
        TypeName=QUEUE_TYPE,
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "VisibilityTimeout": VISIBILITY,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_queue_by_name_quiet(sqs, queue_name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"create did not succeed: status {create_event['OperationStatus']!r}, ErrorCode "
        f"{create_event.get('ErrorCode')!r}, StatusMessage "
        f"{create_event.get('StatusMessage')!r}"
    )
    identifier = create_event["Identifier"]

    as_string = cc.get_resource(TypeName=QUEUE_TYPE, Identifier=identifier)[
        "ResourceDescription"
    ]
    string_props = json.loads(as_string["Properties"])
    assert string_props.get(id_property) == identifier, (
        f"the schema declares {id_property!r} as the primary identifier, but GetResource reports "
        f"{id_property}={string_props.get(id_property)!r} for the resource it identified as "
        f"{identifier!r}; the declared identifier property must hold the identifier"
    )
    assert string_props.get("QueueName") == queue_name, (
        f"GetResource reports QueueName {string_props.get('QueueName')!r}, expected {queue_name!r}"
    )

    as_json = cc.get_resource(
        TypeName=QUEUE_TYPE, Identifier=json.dumps({id_property: identifier})
    )["ResourceDescription"]
    assert as_json["Identifier"] == identifier, (
        f"the JSON identifier {{{id_property!r}: ...}} resolved to Identifier "
        f"{as_json['Identifier']!r}, expected the same {identifier!r}; the response form must not "
        f"follow the request form"
    )
    assert json.loads(as_json["Properties"]) == string_props, (
        f"the JSON and string identifier forms returned different Properties: JSON gave "
        f"{json.loads(as_json['Properties'])!r}, string gave {string_props!r}; both name one "
        f"resource"
    )

    # Identifier resolution happens at the envelope, so this is ValidationException, not the
    # handler-reported InvalidRequestException.
    non_identifier = "VisibilityTimeout"
    assert non_identifier not in [p.rsplit("/", 1)[-1] for p in pointers], (
        f"{non_identifier!r} is the schema's primary identifier for {QUEUE_TYPE}, so it cannot "
        f"serve as this check's non-identifier subject; pointers were {pointers!r}"
    )
    refusal, refusal_message = _error_code(
        lambda: cc.get_resource(
            TypeName=QUEUE_TYPE, Identifier=json.dumps({non_identifier: VISIBILITY})
        )
    )
    assert refusal == "ValidationException", (
        f"a JSON identifier naming the non-identifier property {non_identifier!r} was answered "
        f"{refusal!r}, expected ValidationException; resolving an arbitrary property as an "
        f"identifier -- or answering with some resource anyway -- is over-permissiveness"
    )
    assert refusal_message == f"When specifying the identifier as JSON, you must specify exactly one identifier from [[/properties/{id_property}]], and no additional properties can be specified", (
        f"expected the exact ValidationException message AWS returns, got {refusal_message!r}"
    )

    # The string call still resolves, so the refusal was specific.
    again = cc.get_resource(TypeName=QUEUE_TYPE, Identifier=identifier)["ResourceDescription"]
    assert again["Identifier"] == identifier, (
        f"after the refusal the string-identifier read returned {again['Identifier']!r}, expected "
        f"{identifier!r}"
    )
    native = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]
    assert native["VisibilityTimeout"] == str(VISIBILITY), (
        f"SQS reports VisibilityTimeout {native['VisibilityTimeout']!r} for the queue both "
        f"identifier forms resolved to, expected {str(VISIBILITY)!r}; the identifier must name a "
        f"real queue"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _error_code(fn):
    """The AWS error code and message raised by fn(); raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _delete_queue_by_name_quiet(sqs, queue_name):
    """Teardown, scoped to the one queue this check created."""
    try:
        sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=queue_name)["QueueUrl"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
