"""readonly-retrieve-cannot-mutate-kb-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "readonly-retrieve-cannot-mutate-kb-state"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three identical Retrieve calls against a never-provisioned knowledge base each get
    ResourceNotFoundException: Retrieve creates nothing that would change a later answer."""
    client = ctx.client("bedrock-agent-runtime")
    # Well-formed but never-provisioned knowledge base id (matches ^[0-9a-zA-Z]{10}$).
    knowledge_base_id = "SIM2REAK0B"  # exactly 10 alnum chars, deterministic

    def _retrieve():
        return client.retrieve(
            knowledgeBaseId=knowledge_base_id,
            retrievalQuery={"text": "sim2real behavioral fidelity probe"},
        )

    codes = []
    for _ in range(3):
        code = _error_code(_retrieve)
        codes.append(code)

    assert codes == ["ResourceNotFoundException"] * 3, (
        f"expected ResourceNotFoundException on all 3 identical retrieve calls against "
        f"never-provisioned knowledge base {knowledge_base_id!r}, got {codes}"
    )


def _error_code(fn):
    """Call fn() and return its error code; raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"retrieve against a never-provisioned knowledge base SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
