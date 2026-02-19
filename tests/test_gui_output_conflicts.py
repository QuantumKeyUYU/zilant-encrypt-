from __future__ import annotations

from pathlib import Path

from zilant_encrypt.gui_app import OverwriteDecision, next_available_path, resolve_output_path


def test_next_available_path_for_file(tmp_path: Path) -> None:
    target = tmp_path / "archive.zil"
    target.write_text("x")
    (tmp_path / "archive (1).zil").write_text("x")

    candidate = next_available_path(target)

    assert candidate == tmp_path / "archive (2).zil"


def test_next_available_path_for_directory(tmp_path: Path) -> None:
    target = tmp_path / "restore"
    target.mkdir()
    (tmp_path / "restore (1)").mkdir()

    candidate = next_available_path(target)

    assert candidate == tmp_path / "restore (2)"


def test_resolve_output_path_flow_when_output_exists(tmp_path: Path) -> None:
    existing = tmp_path / "out.zil"
    existing.write_text("old")

    decisions: list[OverwriteDecision] = ["auto_rename"]
    decision_iter = iter(decisions)
    save_as_calls = 0

    def choose_action(_: Path) -> OverwriteDecision:
        return next(decision_iter)

    def choose_save_as(_: Path) -> Path | None:
        nonlocal save_as_calls
        save_as_calls += 1
        return None

    resolved, ow = resolve_output_path(
        existing,
        overwrite_enabled=False,
        choose_action=choose_action,
        choose_save_as=choose_save_as,
    )

    assert resolved == tmp_path / "out (1).zil"
    assert ow is False
    assert save_as_calls == 0


def test_resolve_output_path_overwrite_enabled_keeps_existing(tmp_path: Path) -> None:
    existing = tmp_path / "out.zil"
    existing.write_text("old")

    action_calls = 0

    def choose_action(_: Path) -> OverwriteDecision:
        nonlocal action_calls
        action_calls += 1
        return "cancel"

    resolved, ow = resolve_output_path(
        existing,
        overwrite_enabled=True,
        choose_action=choose_action,
        choose_save_as=lambda _: None,
    )

    assert resolved == existing
    assert ow is True
    assert action_calls == 0


def test_resolve_output_path_new_output_unchanged(tmp_path: Path) -> None:
    fresh = tmp_path / "new.zil"

    resolved, ow = resolve_output_path(
        fresh,
        overwrite_enabled=False,
        choose_action=lambda _: "cancel",
        choose_save_as=lambda _: None,
    )

    assert resolved == fresh
    assert ow is False


def test_resolve_output_path_user_selects_overwrite_enables_effective_flag(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "out.zil"
    existing.write_text("old")

    resolved, ow = resolve_output_path(
        existing,
        overwrite_enabled=False,
        choose_action=lambda _: "overwrite",
        choose_save_as=lambda _: None,
    )

    assert resolved == existing
    assert ow is True
