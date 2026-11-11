"""list-application-dpu-sizes-malformed-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-application-dpu-sizes-malformed-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplicationDPUSizes rejects an out-of-range MaxResults with InvalidRequestException instead
    of clamping it; an unvalidated client sends MaxResults=0 so the rejection is the service's own."""
    athena = ctx.client("athena")

    # Positive control: AWS does not reject a syntactically bogus NextToken for this operation;
    # it is accepted like a first-page request.
    tolerant_response = athena.list_application_dpu_sizes(NextToken="not-a-real-pagination-token!!")
    assert isinstance(tolerant_response.get("ApplicationDPUSizes"), list)

    # the boundary AWS DOES enforce: MaxResults out of its valid range. Client-side parameter
    # validation would otherwise short-circuit this before it ever reaches the wire, so use a
    # client with validation disabled to exercise the real server-side rejection.
    unvalidated = _unvalidated_client(ctx, "athena")
    code, message = _error(lambda: unvalidated.list_application_dpu_sizes(MaxResults=0))
    assert code == "InvalidRequestException", f"CODE={code!r}"
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), f"MESSAGE={message!r}"

    # positive control: a valid MaxResults is accepted
    response = athena.list_application_dpu_sizes(MaxResults=2)
    assert isinstance(response.get("ApplicationDPUSizes"), list)


def _unvalidated_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
