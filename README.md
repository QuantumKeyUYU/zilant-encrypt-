# Zilant Encrypt

Zilant Encrypt — CLI-утилита для шифрования файлов в контейнеры `.zil` на базе AES-256-GCM и Argon2id. MVP спроектирован с учётом будущего добавления гибридного PQ-обмена и скрытых томов.

## Установка

```bash
python -m pip install .
# или dev-зависимости
python -m pip install .[dev]
```

## Использование

```bash
zilenc encrypt input.bin output.zil
zilenc decrypt output.zil restored.bin
zilenc info output.zil
```

Пароль можно передать через `--password`, иначе CLI запросит его интерактивно. Команда `encrypt` умеет принимать директорию, упаковывая её во временный ZIP перед шифрованием.

## Формат контейнера

* Заголовок фиксированной длины 128 байт с полями magic/version, параметрами Argon2id и AAD для всего зашифрованного содержимого.
* Для шифрования содержимого используется случайный `file_key`, зашифрованный (wrapped) ключом, выведенным из пароля; тэг обёртки хранится в заголовке.
* AES-256-GCM и Argon2id из библиотек `cryptography` и `argon2-cffi`.

## Тесты

```bash
pytest -q
```
