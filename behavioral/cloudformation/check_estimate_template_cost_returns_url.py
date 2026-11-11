"""estimate-template-cost-returns-url."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "estimate-template-cost-returns-url"
GROUP = "server-side"
SERVICES = ["cloudformation"]

# The host label and path are fixed; the id is a fresh 40-char lowercase hex token on every call,
# even for byte-identical input (not a content hash).
_FRAGMENT_RE = re.compile(r"/estimate\?id=cloudformation/[0-9a-f]{40}")


def _assert_estimate_url(url):
    """The estimate URL is ``https://calculator.<domain>/#/estimate?id=cloudformation/<40 hex>``.
    The domain is the target's own, so the calculator label leads the host and the path and
    fragment are matched exactly."""
    parts = urlsplit(url) if isinstance(url, str) else None
    labels = (parts.hostname or "").split(".") if parts else []
    assert (parts is not None and parts.scheme == "https" and labels[0] == "calculator"
            and len(labels) > 1 and all(labels[1:]) and parts.path == "/" and not parts.query
            and _FRAGMENT_RE.fullmatch(parts.fragment)), (
        f"expected https://calculator.<domain>/#/estimate?id=cloudformation/<40 lowercase hex>, "
        f"got {url!r}"
    )


@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EstimateTemplateCost returns a pricing-calculator cost-estimate URL for a
    valid template, with a distinct estimate id on every call."""
    cfn = ctx.client("cloudformation")

    template = {
        "Parameters": {"QueueVisibilityTimeout": {"Type": "Number", "Default": 30}},
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": {"Ref": "QueueVisibilityTimeout"}},
            },
        },
    }
    params = [{"ParameterKey": "QueueVisibilityTimeout", "ParameterValue": "45"}]

    url = cfn.estimate_template_cost(TemplateBody=json.dumps(template), Parameters=params)["Url"]
    _assert_estimate_url(url)

    # Same template, same parameters, second call: a hardcoded-URL stub returns
    # the same string twice, real AWS mints a fresh id every time.
    url2 = cfn.estimate_template_cost(TemplateBody=json.dumps(template), Parameters=params)["Url"]
    _assert_estimate_url(url2)
    assert url2 != url, f"expected a distinct estimate id per call, got the same URL twice: {url!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
