from loupe_core.prompt_builder import PromptParts, assemble_messages


def test_stable_and_variable_layers_kept_separate():
    parts = PromptParts(
        common_framing="You are Loupe.",
        project_context="Product: payment API.",
        diff_summary="Changed: refund.py",
        sbom_delta_summary="Added: stripe",
        relevant_artifacts="threats.yaml excerpt",
        lens_system_prompt="You are ThreatLens.",
        lens_task="Identify new threats.",
        prior_findings_handover="",
    )
    msgs = assemble_messages(parts)
    assert len(msgs) == 2
    system, user = msgs
    assert system["role"] == "system"
    assert "You are Loupe." in system["content"]
    assert "payment API" in system["content"]
    assert "Identify new threats." not in system["content"]
    assert user["role"] == "user"
    assert "Identify new threats." in user["content"]


def test_cache_control_marker_on_system():
    parts = PromptParts(
        common_framing="x", project_context="y", diff_summary="z",
        sbom_delta_summary="", relevant_artifacts="",
        lens_system_prompt="", lens_task="task", prior_findings_handover="",
    )
    msgs = assemble_messages(parts)
    assert msgs[0].get("cache_control") == {"type": "ephemeral"}


def test_prior_findings_in_variable_layer():
    parts = PromptParts(
        common_framing="x", project_context="", diff_summary="", sbom_delta_summary="",
        relevant_artifacts="", lens_system_prompt="", lens_task="task",
        prior_findings_handover="From safetylens: asset X is ASIL-D",
    )
    msgs = assemble_messages(parts)
    assert "From safetylens" in msgs[1]["content"]
    assert "From safetylens" not in msgs[0]["content"]
