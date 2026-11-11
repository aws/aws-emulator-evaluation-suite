"""import-api-keys-rollback-on-failonwarnings-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-api-keys-rollback-on-failonwarnings-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys with failOnWarnings=true fails a batch holding one invalid record, yet is not
    transactional: the valid record is still committed and only the invalid one is skipped."""
    apigw = ctx.client("apigateway")

    valid_name = ctx.unique_name("sim2real-rollback-key-")
    valid_key = ("v" + uuid.uuid4().hex + uuid.uuid4().hex)[:40]
    invalid_name = ctx.unique_name("sim2real-rollback-bad-")
    invalid_key = "tooshort1234"

    csv_body = f"Name,Key\n{valid_name},{valid_key}\n{invalid_name},{invalid_key}\n"

    code, message = _error_code(
        lambda: apigw.import_api_keys(body=csv_body.encode("utf-8"), format="csv", failOnWarnings=True)
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException from failOnWarnings=true over a structurally-invalid "
        f"record, got {code}: {message!r}"
    )
    assert message == (
        "Warnings found during import:\n"
        "\tSkipped invalid record: 2. API Key value should be at least 20 characters"
    ), f"the rejection must name the warning it refused to tolerate, got {message!r}"

    # Not a rollback: the otherwise-valid record was already committed before the batch as a
    # whole was reported as failed.
    listed = apigw.get_api_keys(nameQuery=valid_name)["items"]
    assert len(listed) == 1, (
        f"expected the valid record to have been committed despite the failOnWarnings error "
        f"(ImportApiKeys is not transactional), got {listed}"
    )
    for item in listed:
        key_id = item["id"]
        ctx.on_cleanup(lambda k=key_id: apigw.delete_api_key(apiKey=k))
        # ImportApiKeys has no tags parameter, so the key is tagged after creation.
        apigw.tag_resource(
            resourceArn=f"arn:aws:apigateway:{ctx.region}::/apikeys/{key_id}",
            tags={"sim2real": "rollback-on-failonwarnings"},
        )

    invalid_listed = apigw.get_api_keys(nameQuery=invalid_name)["items"]
    assert invalid_listed == [], (
        f"the structurally-invalid record should not have been imported, got {invalid_listed}"
    )


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"the batch was expected to be REJECTED under failOnWarnings=true but succeeded, "
        f"returning {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
