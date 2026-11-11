"""response-request-id-is-a-real-uuid."""
from __future__ import annotations

import re
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "response-request-id-is-a-real-uuid"
GROUP = "representation"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

# AWS RequestId formats differ per service: CloudFormation and Lambda mint UUIDs; DynamoDB mints
# a long uppercase alphanumeric token. Each service is held to the shape it actually uses.
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DDB_RE = re.compile(r"^[A-Z0-9]{40,64}$")
EXPECTED_SHAPE = {
    "cloudformation": ("a UUID", _UUID_RE),
    "lambda": ("a UUID", _UUID_RE),
    "dynamodb": ("a 40-64 char uppercase alphanumeric token", _DDB_RE),
}

# The degenerate value seen in XML responses. A valid UUID BY SHAPE, which is why a shape check
# alone cannot catch it and this is asserted separately.
DEGENERATE = "00000000-0000-0000-0000-000000000000"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every success and error response across three protocol families carries a distinct RequestId
    in its service's format, never empty and never the all-zeros placeholder."""
    seen: dict[str, str] = {}

    # cloudformation is awsQuery/XML (the all-zeros form), dynamodb is awsJson (the empty form), lambda
    # is restJson. All three are cheap reads that create nothing.
    successes = {
        "cloudformation": lambda: ctx.client("cloudformation").list_stacks(),
        "dynamodb": lambda: ctx.client("dynamodb").list_tables(Limit=1),
        "lambda": lambda: ctx.client("lambda").list_functions(MaxItems=1),
    }
    for service, call in successes.items():
        metadata = call()["ResponseMetadata"]
        seen[f"{service}:success"] = _assert_request_id(service, "success", metadata)

    # The empty form appears on JSON error surfaces, so the error path is asserted separately: a
    # target can populate the id on success and drop it while rendering an error envelope.
    errors = {
        "cloudformation": lambda: ctx.client("cloudformation").describe_stacks(
            StackName="sim2real-behav-no-such-stack-" + uuid.uuid4().hex[:8]
        ),
        "dynamodb": lambda: ctx.client("dynamodb").describe_table(
            TableName="sim2real-behav-no-such-table-" + uuid.uuid4().hex[:8]
        ),
        "lambda": lambda: ctx.client("lambda").get_function(
            FunctionName="sim2real-behav-no-such-fn-" + uuid.uuid4().hex[:8]
        ),
    }
    for service, call in errors.items():
        try:
            result = call()
        except ClientError as exc:
            seen[f"{service}:error"] = _assert_request_id(
                service, "error", exc.response.get("ResponseMetadata", {})
            )
            continue
        raise AssertionError(
            f"{service}: the probe named a resource that cannot exist, so this must raise; it returned "
            f"{result!r}"
        )

    # A target that mints one id and reuses it satisfies every assertion above. Six calls, six ids.
    assert len(set(seen.values())) == len(seen), (
        f"every response must carry its OWN RequestId; got {len(set(seen.values()))} distinct ids "
        f"across {len(seen)} calls: {seen!r}"
    )


def _assert_request_id(service: str, surface: str, metadata: dict) -> str:
    """Assert one ResponseMetadata carries a usable RequestId, and return it. Missing, empty, and
    all-zeros are asserted separately as distinct defects."""
    assert "RequestId" in metadata, (
        f"[{service}/{surface}] the response must carry a RequestId; ResponseMetadata was "
        f"{ {k: v for k, v in metadata.items() if k != 'HTTPHeaders'} !r}"
    )
    request_id = metadata["RequestId"]
    assert isinstance(request_id, str) and request_id.strip(), (
        f"[{service}/{surface}] RequestId must be a non-empty string; got {request_id!r}. An empty "
        f"string is one of the two degenerate forms this check exists for"
    )
    assert request_id != DEGENERATE, (
        f"[{service}/{surface}] RequestId must not be the all-zeros placeholder {DEGENERATE!r}. It is a "
        f"syntactically valid UUID, which is why a shape check alone cannot catch it"
    )
    description, pattern = EXPECTED_SHAPE[service]
    assert pattern.match(request_id), (
        f"[{service}/{surface}] RequestId must be {description} for this service; got {request_id!r}. "
        f"Formats differ per service -- measured, not assumed"
    )
    return request_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
