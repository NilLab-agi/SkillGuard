def test_llm_stage_is_skipped_when_not_requested(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill), use_llm=False))]

    assert "meta_analyzer" not in nodes
    assert "deduplicate" in nodes


def test_llm_stage_runs_when_requested(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill), use_llm=True))]

    assert "meta_analyzer" in nodes