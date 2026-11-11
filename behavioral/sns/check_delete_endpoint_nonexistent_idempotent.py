"""delete-endpoint-nonexistent-idempotent."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-endpoint-nonexistent-idempotent"
GROUP = 'platform-application'
SERVICES = ['sns']

def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _account_id(ctx) -> str:
    """Caller account id (STS, with an SNS-topic-ARN fallback for targets without STS)."""
    try:
        return ctx.client("sts").get_caller_identity()["Account"]
    except Exception:
        sns = ctx.client("sns")
        probe = sns.create_topic(Name=f"sim2real-behav-acctprobe-{uuid.uuid4().hex[:8]}")["TopicArn"]
        try:
            return probe.split(":")[4]
        finally:
            try:
                sns.delete_topic(TopicArn=probe)
            except Exception:
                pass

def _bogus_endpoint_arn(ctx, prefix="sim2real-behav-ghost-ep-"):
    """A well-formed but nonexistent endpoint ARN in the caller's account/region."""
    return (f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:endpoint/GCM/"
            f"{prefix}{uuid.uuid4().hex[:8]}/{uuid.uuid4()}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEndpoint on a nonexistent endpoint is idempotent (documented as idempotent)."""
    sns = ctx.client("sns")
    ghost = _bogus_endpoint_arn(ctx)
    # A no-op: DeleteEndpoint on a missing endpoint returns success (a ClientError fails the check).
    sns.delete_endpoint(EndpointArn=ghost)

    # Independent read at the destination: the endpoint must still be genuinely
    # absent, not silently materialized by the "successful" delete.
    read_code, read_message = _error(lambda: sns.get_endpoint_attributes(EndpointArn=ghost))
    assert read_code == "NotFound", (
        f"GetEndpointAttributes after a no-op DeleteEndpoint: expected NotFound, got {read_code}"
    )
    assert read_message == "Endpoint does not exist", (
        f"GetEndpointAttributes after a no-op DeleteEndpoint: unexpected message {read_message!r}"
    )

    # Idempotent means repeatable: the identical delete call must still be a no-op.
    sns.delete_endpoint(EndpointArn=ghost)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
