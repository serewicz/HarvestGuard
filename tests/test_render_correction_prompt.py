from scripts.render_correction_prompt import render


def test_rendered_prompt_has_cycle_and_exact_context_path():
    prompt = render(2, "/runner/temp/correction_context.json")
    assert "correction cycle 2 (of at most 3)" in prompt
    assert "/runner/temp/correction_context.json" in prompt
    assert "__CYCLE__" not in prompt
    assert "__CONTEXT_PATH__" not in prompt


def test_rendered_cycles_differ_only_by_cycle_number():
    first = render(1, "/tmp/context.json")
    second = render(2, "/tmp/context.json")
    assert first != second
    assert first.replace("cycle 1", "cycle 2") == second
