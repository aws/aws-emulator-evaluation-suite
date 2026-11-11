"""malformed-access-key-rejected-consistently."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-access-key-rejected-consistently"
GROUP = "identity"
SERVICES = ["dynamodb", "iam", "sts"]

# A syntactically valid secret shape, paired with a per-run access key id below so this is never the
# canonical documentation key that a target could special-case.
_BOGUS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# The query-protocol services answer InvalidClientTokenId while DynamoDB's JSON protocol answers
# UnrecognizedClientException; only the message is uniform across services.
EXPECTED_CODES = {
    "sts": "InvalidClientTokenId",
    "iam": "InvalidClientTokenId",
    "dynamodb": "UnrecognizedClientException",
}
CANONICAL_MESSAGE = "The security token included in the request is invalid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unissued access key is refused by sts, iam and dynamodb with one security-token message.

    Each service uses its own protocol's code; the real credentials succeed on all three first.
    """
    bogus_key = "AKIA" + uuid.uuid4().hex.upper()[:16]
    bogus = {"aws_access_key_id": bogus_key, "aws_secret_access_key": _BOGUS_SECRET}

    # Controls first, so a refusal is attributable to the credential, not an unreachable service.
    ctx.client("sts").get_caller_identity()
    ctx.client("iam").list_account_aliases()
    ctx.client("dynamodb").list_tables(Limit=1)

    # All codes are collected before asserting, so a failure names every service that disagreed.
    probes = {
        "sts": lambda c: c.get_caller_identity(),
        "iam": lambda c: c.list_account_aliases(),
        "dynamodb": lambda c: c.list_tables(Limit=1),
    }
    observed: dict[str, tuple[str, str]] = {}
    for service, call in probes.items():
        client = ctx.client(service, creds=bogus)
        try:
            result = call(client)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            observed[service] = (error.get("Code", "<none>"), error.get("Message", ""))
            continue
        raise AssertionError(
            f"{service} ACCEPTED an access key that was never issued ({bogus_key!r}) and returned "
            f"{result!r}. Accepting unissued credentials is the defect this check exists for -- the "
            f"other services refused it: {observed!r}"
        )

    assert {svc: code for svc, (code, _) in observed.items()} == EXPECTED_CODES, (
        f"each service must refuse with the code real AWS uses for it ({EXPECTED_CODES!r}); got "
        f"{ {svc: code for svc, (code, _) in observed.items()} !r}"
    )
    for service, (_, message) in observed.items():
        assert message == CANONICAL_MESSAGE, (
            f"[{service}] the refusal must carry the canonical security-token message "
            f"({CANONICAL_MESSAGE!r}) -- that is the part AWS keeps uniform across protocols; got "
            f"{message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
