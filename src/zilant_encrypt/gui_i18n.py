"""Localization helpers for the Zilant Encrypt GUI."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Lang = Literal["en", "ru"]


@dataclass(frozen=True)
class Strings:
    app_title: str
    subtitle: str
    tab_encrypt: str
    tab_inspect: str
    about: str
    action_label: str
    encrypt: str
    decrypt: str
    input_output_group: str
    source_type: str
    single_file: str
    directory_zip: str
    input_path: str
    output_path: str
    select_input_ph: str
    select_output_ph: str
    browse: str
    overwrite_checkbox: str
    overwrite_tooltip: str
    security_group: str
    mode_standard: str
    mode_pq: str
    mode_standard_tt: str
    mode_pq_tt: str
    password_ph: str
    show_password: str
    decoy_group: str
    decoy_subtitle: str
    decoy_password: str
    decoy_select_ph: str
    decoy_tooltip: str
    decrypt_target_label: str
    auto_volume: str
    force_main: str
    force_decoy: str
    start_encrypt: str
    start_decrypt: str
    inspect_group: str
    inspect_select_ph: str
    inspect_verify: str
    inspect_password_ph: str
    inspect_button: str
    status_ready: str
    status_processing: str
    status_error: str
    open_folder: str
    dialog_select_folder_encrypt: str
    dialog_select_file: str
    dialog_save_container: str
    dialog_select_output_dir: str
    dialog_select_decoy_folder: str
    dialog_select_decoy_file: str
    dialog_select_container: str
    overwrite_prompt_title: str
    overwrite_prompt_body: str
    input_missing: str
    password_required: str
    decoy_password_required: str
    container_not_found: str
    success_title: str
    error_title: str
    processing_success: str
    processing_invalid_password: str
    processing_requires_pq: str
    processing_integrity_error: str
    processing_unexpected_error: str
    about_title: str
    about_body: str
    overview_file: str
    overview_version: str
    overview_volumes: str
    overview_label_main: str
    overview_label_decoy: str
    overview_mode_pq: str
    overview_mode_pw: str
    overview_status_ok: str
    overview_status_not_checked: str
    overview_status_skipped: str
    overview_pq_available: str
    overview_pq_missing: str
    password_strength_weak: str
    password_strength_fair: str
    password_strength_good: str
    password_strength_strong: str


STRINGS: dict[Lang, Strings] = {
    "en": Strings(
        app_title="Zilant Encrypt",
        subtitle="Secure containers · Decoy volumes · Post-Quantum Hybrid",
        tab_encrypt="Encrypt / Decrypt",
        tab_inspect="Inspect / Audit",
        about="About",
        action_label="Action:",
        encrypt="Encrypt",
        decrypt="Decrypt",
        input_output_group="Input / Output",
        source_type="Source Type:",
        single_file="Single File",
        directory_zip="Directory (Zip)",
        input_path="Input Path",
        output_path="Output Path",
        select_input_ph="Select Input...",
        select_output_ph="Select Output...",
        browse="Browse",
        overwrite_checkbox="Overwrite existing files without asking",
        overwrite_tooltip="Replace output automatically if it already exists.",
        security_group="Security",
        mode_standard="Standard (AES-256-GCM + Argon2id)",
        mode_pq="PQ-Hybrid (Kyber768 + AES)",
        mode_standard_tt="Best compatibility for everyday encryption.",
        mode_pq_tt="Future-proof against quantum attacks; requires liboqs.",
        password_ph="Enter secure password",
        show_password="Show password",
        decoy_group="Decoy Volume (Plausible Deniability)",
        decoy_subtitle=(
            "Create a hidden volume inside the main container. It uses its own password."
        ),
        decoy_password="Decoy Password",
        decoy_select_ph="Select Decoy Payload...",
        decoy_tooltip="A decoy volume hides less-sensitive data behind another password.",
        decrypt_target_label="Decrypt Target:",
        auto_volume="Auto-detect Volume",
        force_main="Force Main",
        force_decoy="Force Decoy",
        start_encrypt="START ENCRYPTION",
        start_decrypt="START DECRYPTION",
        inspect_group="Container to Inspect",
        inspect_select_ph="Select .zil container...",
        inspect_verify="Verify Integrity (requires password)",
        inspect_password_ph="Password",
        inspect_button="Analyze Container",
        status_ready="Ready",
        status_processing="Processing... Please wait.",
        status_error="Error occurred",
        open_folder="Open Folder",
        dialog_select_folder_encrypt="Select Folder to Encrypt",
        dialog_select_file="Select File",
        dialog_save_container="Save Container As",
        dialog_select_output_dir="Select Output Directory",
        dialog_select_decoy_folder="Select Decoy Folder",
        dialog_select_decoy_file="Select Decoy File",
        dialog_select_container="Select Container",
        overwrite_prompt_title="Overwrite?",
        overwrite_prompt_body="Output exists:\n{path}\n\nOverwrite?",
        input_missing="Input path does not exist.",
        password_required="Password is required.",
        decoy_password_required="Decoy password required",
        container_not_found="Container not found.",
        success_title="Success",
        error_title="Error",
        processing_success="Operation completed successfully.",
        processing_invalid_password="Invalid password or key.",
        processing_requires_pq=(
            "Operation requires PQ support (liboqs) which is missing."
        ),
        processing_integrity_error="Data integrity/format error: {error}",
        processing_unexpected_error="Unexpected error: {error}",
        about_title="About Zilant Encrypt",
        about_body=(
            "<h3>Zilant Encrypt v{version}</h3>"
            "<p>Secure, local-only encryption tool.</p>"
            "<p>Features: <b>Argon2id</b>, <b>AES-GCM</b>, "
            "<b>Kyber768 (PQ)</b>, <b>Decoy Volumes</b>.</p>"
            "<p>License: MIT</p>"
        ),
        overview_file="File: {path}",
        overview_version="Version: v{version}",
        overview_volumes="Volumes:",
        overview_label_main="main",
        overview_label_decoy="decoy",
        overview_mode_pq="pq-hybrid",
        overview_mode_pw="password",
        overview_status_ok="OK",
        overview_status_not_checked="NOT CHECKED",
        overview_status_skipped="SKIPPED (no password)",
        overview_pq_available="PQ support: available",
        overview_pq_missing="PQ support: not available",
        password_strength_weak="Weak",
        password_strength_fair="Fair",
        password_strength_good="Good",
        password_strength_strong="Strong",
    ),
    "ru": Strings(
        app_title="Zilant Encrypt",
        subtitle="Надёжные контейнеры · Двойной пароль · PQ-гибрид",
        tab_encrypt="Шифрование / Расшифровка",
        tab_inspect="Проверка контейнера",
        about="О приложении",
        action_label="Действие:",
        encrypt="Зашифровать",
        decrypt="Расшифровать",
        input_output_group="Вход / Выход",
        source_type="Тип источника:",
        single_file="Один файл",
        directory_zip="Папка (Zip)",
        input_path="Путь к исходнику",
        output_path="Путь для сохранения",
        select_input_ph="Выбрать исходный файл или папку...",
        select_output_ph="Выбрать путь сохранения...",
        browse="Обзор",
        overwrite_checkbox="Перезаписывать без вопросов",
        overwrite_tooltip="Если включено — готов заменять существующий результат автоматически.",
        security_group="Безопасность",
        mode_standard="Стандарт (AES-256-GCM + Argon2id)",
        mode_pq="PQ-гибрид (Kyber768 + AES)",
        mode_standard_tt="Оптимально для повседневного использования и совместимости.",
        mode_pq_tt="Для будущей защиты от квантовых атак, нужен liboqs.",
        password_ph="Введите надёжный пароль",
        show_password="Показать пароль",
        decoy_group="Ложный том (правдоподобное отрицание)",
        decoy_subtitle=(
            "Спрятать второй том внутри основного. Для него нужен отдельный пароль."
        ),
        decoy_password="Пароль ложного тома",
        decoy_select_ph="Выбрать данные для ложного тома...",
        decoy_tooltip=(
            "Ложный том хранит менее важные данные под другим паролем — на случай давления."
        ),
        decrypt_target_label="Что расшифровывать:",
        auto_volume="Определить автоматически",
        force_main="Только основной",
        force_decoy="Только ложный",
        start_encrypt="НАЧАТЬ ШИФРОВАНИЕ",
        start_decrypt="НАЧАТЬ РАСШИФРОВКУ",
        inspect_group="Контейнер для проверки",
        inspect_select_ph="Выбрать .zil контейнер...",
        inspect_verify="Проверить целостность (нужен пароль)",
        inspect_password_ph="Пароль",
        inspect_button="Анализ контейнера",
        status_ready="Готово",
        status_processing="В работе... Пожалуйста, подождите.",
        status_error="Произошла ошибка",
        open_folder="Открыть папку",
        dialog_select_folder_encrypt="Выбрать папку для шифрования",
        dialog_select_file="Выбрать файл",
        dialog_save_container="Сохранить контейнер как",
        dialog_select_output_dir="Выбрать папку для результата",
        dialog_select_decoy_folder="Папка для ложного тома",
        dialog_select_decoy_file="Файл для ложного тома",
        dialog_select_container="Выбрать контейнер",
        overwrite_prompt_title="Перезаписать?",
        overwrite_prompt_body="Результат уже существует:\n{path}\n\nПерезаписать?",
        input_missing="Исходный путь не найден.",
        password_required="Нужен пароль.",
        decoy_password_required="Требуется пароль для ложного тома",
        container_not_found="Контейнер не найден.",
        success_title="Готово",
        error_title="Ошибка",
        processing_success="Операция успешно завершена.",
        processing_invalid_password="Неверный пароль или ключ.",
        processing_requires_pq="Нужна поддержка PQ (liboqs отсутствует).",
        processing_integrity_error="Ошибка формата/целостности: {error}",
        processing_unexpected_error="Неожиданная ошибка: {error}",
        about_title="О Zilant Encrypt",
        about_body=(
            "<h3>Zilant Encrypt v{version}</h3>"
            "<p>Локальный инструмент шифрования.</p>"
            "<p>Возможности: <b>Argon2id</b>, <b>AES-GCM</b>, "
            "<b>Kyber768 (PQ)</b>, <b>ложные тома</b>.</p>"
            "<p>Лицензия: MIT</p>"
        ),
        overview_file="Файл: {path}",
        overview_version="Версия: v{version}",
        overview_volumes="Тома:",
        overview_label_main="основной",
        overview_label_decoy="ложный",
        overview_mode_pq="pq-гибрид",
        overview_mode_pw="пароль",
        overview_status_ok="OK",
        overview_status_not_checked="НЕ ПРОВЕРЕНО",
        overview_status_skipped="ПРОПУЩЕНО (нет пароля)",
        overview_pq_available="PQ: доступно",
        overview_pq_missing="PQ: недоступно",
        password_strength_weak="Слабый",
        password_strength_fair="Средний",
        password_strength_good="Хороший",
        password_strength_strong="Надёжный",
    ),
}


def get_strings(lang: Lang) -> Strings:
    """Return localized strings, defaulting to English."""

    return STRINGS.get(lang, STRINGS["en"])
