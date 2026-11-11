"""oidc-provider-tag-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oidc-provider-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags attach to an OIDC provider via TagOpenIDConnectProvider, are visible via
    ListOpenIDConnectProviderTags, and a targeted key disappears after
    UntagOpenIDConnectProvider while an untouched key survives."""
    iam = ctx.client("iam")
    url = f"https://sim2real-oidc.example.com/{ctx.unique_name('idp-')}"

    resp = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"],
        ClientIDList=["sts.amazonaws.com"],
    )
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    _retry_until_success(
        lambda: iam.tag_open_id_connect_provider(
            OpenIDConnectProviderArn=arn,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags = _tagmap(iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"])
    assert tags.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test after TagOpenIDConnectProvider, got {tags}"
    )
    assert tags.get("Owner") == "behavioral-suite", (
        f"expected Owner=behavioral-suite after TagOpenIDConnectProvider, got {tags}"
    )

    iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"])
    assert "Environment" not in tags_after, (
        f"expected Environment removed after UntagOpenIDConnectProvider, got {tags_after}"
    )
    assert tags_after.get("Owner") == "behavioral-suite", (
        f"expected untouched Owner tag to survive UntagOpenIDConnectProvider, got {tags_after}"
    )


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _retry_until_success(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
