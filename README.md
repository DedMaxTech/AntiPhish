# AntiPhish

Локальный анализатор фишинговых писем, сайтов и вложений. Версия 2.8.

Система извлекает ссылки, восстанавливает переходы, проверяет формы и получателей данных, распознаёт текст и логотипы. CLI, FastAPI и веб-интерфейс используют один анализатор. Отчёт содержит JSON, основания результата и доступные фрагменты текста, кода и изображений.

## Возможности

- EML, HTML, URL, PDF, изображения и документы Office; пакетная обработка папок, ZIP и TAR.
- Проверка полей пароля, OTP, карты и seed-фразы, адресов отправки форм и простых сборщиков JavaScript.
- Цепочки переадресаций, почтовые обёртки, опубликованные Google-таблицы, QR и вложенные документы.
- Русский OCR, рендер писем с CID и доступными внешними картинками, графическое сопоставление логотипов.
- Сопоставление заявленного сервиса с доменом страницы, отправителем и получателем секрета.
- Проверки социальных сценариев: запрос секрета в переписке, комиссия перед выплатой, «безопасный счёт», ClickFix, удалённое управление под банковским предлогом.
- Локальные репутационные списки, точные отпечатки, похожие размеченные письма и шаблоны страниц.
- Опциональные Laya, Horizon и Qwen; отдельная пометка для предупреждений по оценке ИИ.
- История проверок и управление образцами в веб-интерфейсе.

В каталоге 156 брендов. В поставляемой галерее 284 изображения для 113 брендов; часть изображений является вариациями размера или фона. Наличие названия или логотипа само по себе не означает фишинг.

## Установка

Нужен Python 3.11 или новее. Рекомендуется отдельное виртуальное окружение.

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[api,ocr,active]'
python -m playwright install --with-deps chromium
python -m antiphish setup-ocr
python -m antiphish serve
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[api,ocr,active]'
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m antiphish setup-ocr
.\.venv\Scripts\python.exe -m antiphish serve
```

Интерфейс: http://127.0.0.1:8000/. Swagger: http://127.0.0.1:8000/docs. Команда `python -m antiphish gui` также запускает веб-интерфейс и открывает браузер.

Для текстовых моделей установите `python -m pip install -e '.[deep]'`, затем выполните `python -m antiphish setup-laya` и `python -m antiphish setup-text-model`. Веса Qwen загружаются отдельно в `models/Qwen3.5-4B` либо указываются через `ANTIPHISH_LLM_MODEL_DIR`. Анализ использует только уже установленные локальные модели. Состояние компонентов показывает `python -m antiphish doctor`.

## Профили и сеть

| Профиль | Состав по умолчанию |
|---|---|
| fast | Разбор структуры, правил и локальных баз, без OCR, QR и рендера |
| quality | Дополнительно OCR, QR, графический поиск и локальный рендер |
| deep | Дополнительно Laya, Horizon и Qwen |
| custom | Собственный набор компонентов |

Веб-интерфейс позволяет менять компоненты и лимиты. CLI принимает `--options-file settings.json`, API принимает объект `options`. Например: `{"laya":true,"text_model":true,"llm":false,"max_network_pages":8}`. Полный список находится в `src/antiphish/options.py`.

| Сеть | Поведение |
|---|---|
| offline | Без посещения внешних сайтов |
| http | Ограниченная загрузка страниц и доступных изображений без выполнения JavaScript |
| browser | Изолированный Chromium, JavaScript, снимки и ограниченная проверка динамических форм |

Browser требует `--confirm-browser-risk I_UNDERSTAND` либо соответствующее разрешение в веб. Проверка не использует пользовательские cookies, не вводит реальные пароли и блокирует отправку форм. Для статического рендера письма JavaScript и внешняя сеть отключены.

## Команды

```bash
python -m antiphish analyze samples/benign-corporate.eml --profile fast --network offline --json
python -m antiphish analyze message.eml --profile quality --network http --output result.json
python -m antiphish analyze message.eml --profile deep --network browser --confirm-browser-risk I_UNDERSTAND --persist
python -m antiphish batch samples --profile quality --network offline --output batch.json
python -m antiphish batch messages.zip --network offline --output batch.json --resume
python -m antiphish update-feeds
python -m antiphish feed-status
python -m antiphish import-logos my-logos
python -m antiphish --help
```

Репутационные списки скачиваются отдельной командой и используются локально. Обновление не запускается на каждое письмо. Веса моделей, личные письма, история и пользовательская база в репозиторий не входят.

## API

Основные методы: `POST /analyze`, `POST /analyze/file`, `POST /batch`, `POST /batch/file`. Параметры и форматы файлов доступны в Swagger. Пример JSON для `/analyze`:

```json
{"source":"/inputs/message.eml","profile":"quality","network":"http","persist":true}
```

История: `GET /reports`, `GET /reports/{id}`. Управление образцами: `POST /reviews`, `DELETE /reviews/{id}`. Каталог оснований: `GET /reasons`. Состояние системы: `GET /health`, `GET /components`, `GET /knowledge`.

API рассчитан на внутренние вызовы, авторизации нет. По умолчанию сервер слушает только localhost.

## Результат

| Вердикт | Значение |
|---|---|
| PHISHING | Есть конкретное сильное основание: подтверждённый индикатор/образец или подтверждённая подмена с получателем секрета |
| SUSPICIOUS | Есть подозрительный сценарий, маршрут, сходство или модельное предупреждение, требующее проверки |
| NOT_DETECTED | Выполненные проверки не нашли достаточных оснований |

Полнота анализа записывается отдельно в `analysis_status`: COMPLETE, PARTIAL или FAILED. Сетевой сбой, неизвестный домен, CAPTCHA, картинка бренда или один высокий балл модели сами по себе не подтверждают фишинг. NOT_DETECTED не гарантирует безопасность недоступной или неполностью проверенной страницы.

## Данные и расширение базы

В checkout рабочие данные находятся в `artifacts/`, `reports/` и `models/`. В установленном пакете используется пользовательский каталог данных. Пути задаются через `ANTIPHISH_DATA_DIR` и `ANTIPHISH_MODEL_DIR`. Остальные переменные описаны в [.env.example](.env.example); файл не загружается автоматически, значения нужно передать процессу.

Письмо можно разметить в веб после проверки. Сохраняются точный хеш, нормализованная текстовая сигнатура, метка, комментарий и связь с отчётом. Эталоны страниц с формами добавляются по выбору пользователя. Для похожих писем и форм используются отдельные ограничения сходства и контекста; положительный образец не разрешает весь домен.

Пользовательские логотипы импортируются из папки с `manifest.jsonl`; формат и проверки находятся в `src/antiphish/logogallery.py`. Галерея и каталог доменов дополняются отдельно от размеченных писем.

## Docker

```bash
# OCR-веса должны быть подготовлены в ./models до запуска контейнера
python -m antiphish setup-ocr
docker compose up --build -d
```

Образ использует Debian 12 и Python 3.12, по умолчанию содержит API, OCR, анализ Office и Chromium. Модели подключаются из `./models` только для чтения. Файлы `./samples` доступны как `/inputs`, рабочие данные сохраняются в Docker volume. Процесс работает без root; основной filesystem read-only. Deep-зависимости добавляются сборочным аргументом `EXTRAS=api,ocr,active,deep`; GPU и веса настраиваются отдельно.

## Проверка качества

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m antiphish benchmark-dataset /path/to/labelled.zip --profile fast --network offline --output metrics.json
python -m antiphish audit-dataset /path/to/labelled.zip --output-dir audit
python scripts/acceptance_snapshot.py --output stand.json
```

Функциональные тесты проверяют разбор файлов, правила, сетевые ограничения, API и сохранение доказательств. Часть проверок OCR/браузера пропускается, если соответствующие компоненты не установлены. Метрики по знакомым данным разработки не являются независимой оценкой. Для итоговой оценки нужны проверенные метки, отрицательные письма, разделение по кампаниям и сохранённое состояние страниц; доступность текущих URL учитывается отдельно.

## Структура и документация

- `src/antiphish/`: анализатор, извлечение, правила, модели, CLI, API и веб.
- `resources/`: публичный каталог брендов, доменов и галерея изображений с происхождением.
- `tests/`: функциональные и регрессионные проверки.
- `samples/`: небольшие искусственные примеры.
- `scripts/`: воспроизводимая фиксация стенда и сравнение текстовых моделей.
