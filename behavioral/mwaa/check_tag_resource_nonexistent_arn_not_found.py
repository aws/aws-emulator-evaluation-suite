"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a well-formed ARN of a nonexistent environment fails with NotFoundException
    "Resource was not found".
    """
    mwaa = ctx.client("mwaa")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-mwaa-missing-")
    arn = f"arn:aws:airflow:{ctx.region}:{account_id}:environment/{name}"

    code, message = _error(lambda: mwaa.tag_resource(ResourceArn=arn, Tags={"k": "v"}))
    assert code == "NotFoundException", f"code={code!r}"
    assert message == "Resource was not found", f"message={message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

