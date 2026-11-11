"""describe-voices-contains-known-voice."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-voices-contains-known-voice"
GROUP = "state"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The unfiltered DescribeVoices catalog contains the well-known Joanna voice with its
    correct gender, language, and engine metadata."""
    polly = ctx.client("polly")
    voices = {}
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = polly.describe_voices(**kwargs)
        for v in resp["Voices"]:
            voices[v["Id"]] = v
        token = resp.get("NextToken")
        if not token:
            break

    assert "Joanna" in voices, sorted(voices)
    joanna = voices["Joanna"]
    assert joanna["LanguageCode"] == "en-US", joanna
    assert joanna["Gender"] == "Female", joanna
    assert "standard" in joanna["SupportedEngines"], joanna
    assert "neural" in joanna["SupportedEngines"], joanna


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
