"""list-tags-unknown-resource-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-unknown-resource-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a nonexistent domain ARN returns UnknownResourceFault rather than an empty tag list,
    while the same call against a real, tagged domain ARN returns its tags."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-domain-")
    swf.register_domain(
        name=domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "env", "value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, domain))

    arn = swf.describe_domain(name=domain)["domainInfo"]["arn"]

    # Positive control: a real, tagged domain ARN returns its tags without error.
    tag_list = swf.list_tags_for_resource(resourceArn=arn)["tags"]
    got_tags = {t["key"]: t["value"] for t in tag_list}
    assert got_tags == {"env": "sim2real"}, f"expected tags {{'env': 'sim2real'}}, got {got_tags}"

    bogus_domain = domain + "-does-not-exist"
    bogus_arn = arn + "-does-not-exist"

    # Corroborate: the domain the bogus ARN points at genuinely does not exist.
    describe_code, describe_message = _error(lambda: swf.describe_domain(name=bogus_domain))
    assert describe_code == "UnknownResourceFault", (
        f"expected DescribeDomain on a never-registered domain to raise UnknownResourceFault, got {describe_code!r}"
    )
    expected = f"Unknown domain: {bogus_domain}"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    code, message = _error(lambda: swf.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "UnknownResourceFault", (
        f"expected ListTagsForResource on a nonexistent domain ARN to raise UnknownResourceFault, got {code!r}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_deprecate(swf, name):
    try:
        # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
        swf.deprecate_domain(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DomainDeprecatedFault", "UnknownResourceFault"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
