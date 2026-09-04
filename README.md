# AntiPhish

AntiPhish - локальная программа для проверки писем на фишинг. На вход можно дать `.eml`, сырой MIME, HTML, URL, PDF, документ Office или изображение с QR-кодом. На выходе будут вердикт, причины и найденные признаки.

Письма никуда не отправляются. По умолчанию программа вообще не использует сеть.

## Быстрый запуск

Готовое окружение уже находится в проекте:

```powershell
.\.venv\Scripts\python.exe -m antiphish doctor
.\.venv\Scripts\python.exe -m antiphish analyze .\samples\benign-corporate.eml
.\.venv\Scripts\python.exe -m antiphish gui
```

Проверка своего письма:

```powershell
.\.venv\Scripts\python.exe -m antiphish analyze "C:\Mail\message.eml" --profile quality --network offline
```

JSON-результат:

```powershell
.\.venv\Scripts\python.exe -m antiphish analyze "C:\Mail\message.eml" --profile quality --network offline --json
```

Исходник письма или HTML можно передать через stdin:

```powershell
Get-Content .\message.eml -Raw | .\.venv\Scripts\python.exe -m antiphish analyze - --json
```

## Профили анализа

Профиль меняет глубину и время анализа, а не порог строгости.

| Профиль | Что делает | Когда использовать |
|---|---|---|
| `fast` | Статически разбирает письмо, HTML, URL и вложения с уменьшенными лимитами. Не декодирует QR и не извлекает изображения из PDF | Для быстрой предварительной проверки |
| `quality` | Выполняет полный статический разбор, включая QR, pHash изображений, PDF и Office | Обычный рекомендуемый режим |
| `deep` | Делает всё из `quality` и добавляет локальный разбор текста и изображения моделями Qwen и SigLIP | Для ручной проверки сложных писем и BEC |

На небольшом обычном HTML `fast` и `quality` могут дать одинаковый результат. Если там нет QR, PDF с картинками или других тяжёлых объектов, оба профиля находят одни и те же факты.

`deep` тоже не обязан менять вердикт. Вывод модели используется как дополнительная подсказка и не может самостоятельно поставить `PHISHING`. Это сделано специально, чтобы ошибка модели не заблокировала нормальную корпоративную почту.

Выбранный профиль, включённые этапы и результаты моделей теперь видны в GUI в разделе "Режим анализа". В JSON это поля `configuration` и `model_evidence`.

## Сетевые режимы

| Режим | Что происходит |
|---|---|
| `offline` | Ссылки не открываются. Анализируются только переданные данные |
| `http` | Без JavaScript загружается до пяти ссылок из письма. Каждый редирект проходит SSRF-проверку |
| `browser` | До двух ссылок открываются в отдельном временном контексте Edge с JavaScript |

Проверка отдельного URL:

```powershell
.\.venv\Scripts\python.exe -m antiphish analyze "https://example.org/page" --network http --json
```

Активный browser-режим в CLI требует явного подтверждения:

```powershell
.\.venv\Scripts\python.exe -m antiphish analyze "https://example.org/page" --network browser --confirm-browser-risk I_UNDERSTAND --json
```

В GUI подтверждение показывается отдельным окном.

Раньше сетевой переключатель в GUI влиял только на случай, когда входом был сам URL. Для EML и HTML найденные ссылки не открывались, поэтому результат действительно не менялся. Сейчас это исправлено: `http` и `browser` обрабатывают также ссылки, извлечённые из письма.

После сетевого анализа вердикт всё равно может остаться прежним. Сеть добавляет данные о конечной странице и редиректах, но не обязана менять уже обоснованное решение. Если ссылок нет, режимам просто нечего загружать. Ссылки с токенами и чувствительными query-параметрами намеренно не открываются.

## GUI

```powershell
.\.venv\Scripts\python.exe -m antiphish gui
```

В окне можно выбрать файл или вставить MIME/HTML. После анализа показываются:

- вердикт и полнота анализа;
- выбранный профиль и включённые этапы;
- сетевые попытки и их статус;
- reason codes;
- найденные URL и вложения;
- вывод локальных моделей для `deep`;
- кнопка сохранения полного JSON.

## Вердикты

- `NOT_DETECTED` - достаточных доказательств не найдено. Это не гарантия безопасности.
- `SUSPICIOUS` - письмо лучше отправить на ручную проверку или в карантин.
- `PHISHING` - найден точный подтверждённый IOC либо составная цепочка доказательств.

Для составного `PHISHING` обычно одновременно нужны:

1. намерение получить пароль, OTP, данные карты или другую чувствительную информацию;
2. внешний получатель введённых данных;
3. независимое несоответствие домена, бренда, ссылки, QR или отправителя.

Одиночные слова вроде "срочно", "счёт" или "оплата" ничего не блокируют. Одного несовпадения `From` и `Reply-To` тоже недостаточно.

Коды завершения CLI:

- `0` - `NOT_DETECTED`;
- `10` - `SUSPICIOUS`;
- `20` - `PHISHING`;
- `30` - ошибка анализа.

## Какие данные разбираются

- EML и raw MIME: заголовки, тело, HTML-части и вложения;
- HTML: DOM, формы, поля ввода, ссылки, JavaScript API и редиректы;
- URL: IDNA, Unicode/confusable-признаки, IP, сокращатели и query-токены;
- PDF: текст, ссылки, формы, изображения и активные действия;
- Office: OOXML relationships, ссылки, XML и макросы без их запуска;
- изображения: pHash и QR-коды;
- вложенные объекты: ограниченный рекурсивный разбор.

## Бренды

В основной базе сейчас 75 активных брендов с известными официальными доменами. Есть российские банки, государственные порталы, операторы, магазины, службы доставки, транспорт, платёжные и корпоративные сервисы.

Неизвестный бренд программа тоже может обнаружить. Формы кражи пароля, внешняя отправка данных, подмена ссылок, BEC, QR-фишинг и фальшивые просмотрщики определяются общими правилами и не зависят от списка брендов.

Исходная база находится в `resources/brands.json`. После её изменения runtime-артефакты обновляются командой:

```powershell
.\.venv\Scripts\python.exe -c "from antiphish.kb import export_runtime_artifacts; export_runtime_artifacts()"
```

## База знаний

Основной файл - `artifacts/knowledge.sqlite`. В нём находятся:

- подтверждённые SHA-256 и URL IOC;
- DOM, JS и form fingerprints;
- pHash изображений;
- бренды и официальные домены;
- происхождение данных и версия схемы.

Повторная сборка по данным кейса:

```powershell
.\.venv\Scripts\python.exe -m antiphish build-kb --case-dir "C:\Path\To\Dataset"
```

Генерируются `knowledge.sqlite`, `fingerprints.jsonl`, `sha256-manifest.csv`, `brands.json`, `brands.npz`, `rules.json`, `iocs.txt` и `antiphish.yar`.

Широкие блокирующие YARA-сигнатуры намеренно не создаются без проверки на нормальной почте. Точный SHA-256 подтверждённого объекта остаётся отдельным сильным признаком.


## Безопасность

- макросы, JavaScript из вложений и исполняемые файлы не запускаются;
- XML разбирается без внешних сущностей и сети;
- для архивов ограничены количество файлов, полный размер и коэффициент сжатия;
- ограничены размер входа, число URL, страниц PDF, изображений и глубина вложений;
- `http` и `browser` проверяют IP каждого перехода и блокируют private/reserved адреса;
- значения токенов редактируются в отчётах;
- сырой вход автоматически не сохраняется;
- ошибка дополнительного парсера даёт `PARTIAL` и не усиливает составной блокирующий вердикт.

Browser-режим всё равно лучше запускать в отдельной VM. Изоляция браузера не отменяет возможные серверные последствия обычного GET-запроса.

## Установка с нуля

Базовое окружение:

```powershell
cd D:\Projects\AntiPhish
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Если CUDA PyTorch уже установлен в основном Python, его можно использовать без повторной загрузки:

```powershell
python -m venv --system-site-packages .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev,deep]" huggingface-hub
```

Загрузка моделей:

```powershell
.\.venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('Qwen/Qwen3.5-4B', local_dir=r'D:\Projects\AntiPhish\models\Qwen3.5-4B'); snapshot_download('google/siglip2-base-patch16-224', local_dir=r'D:\Projects\AntiPhish\models\siglip2-base-patch16-224')"
```

Проверка CUDA:

```powershell
.\.venv\Scripts\python.exe -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"
```

## Тесты и benchmark

Все тесты:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Встроенная быстрая проверка:

```powershell
.\.venv\Scripts\python.exe -m antiphish benchmark
```

Проверка всего HTML-корпуса кейса:

```powershell
.\.venv\Scripts\python.exe -m antiphish benchmark --case-dir "C:\Path\To\Dataset"
```

Проверка SpamAssassin:

```powershell
.\.venv\Scripts\python.exe -m antiphish benchmark `
  --spamassassin-ham C:\Corpora\20030228_easy_ham.tar.bz2 `
  --spamassassin-ham C:\Corpora\20030228_easy_ham_2.tar.bz2 `
  --spamassassin-ham C:\Corpora\20030228_hard_ham.tar.bz2
```

На текущей версии выполнен 41 unit/security/integration тест.

Результаты уже проведённых проверок:

- исходный ZIP: 7 642 HTML и 2 854 PNG, включая 86 длинных путей;
- 10 496 fingerprint-записей без ошибок;
- 9 913 уникальных SHA-256 и 583 дубля;
- поведенческий recall `PHISHING + SUSPICIOUS` на HTML кейса без точных IOC - 91,939%;
- SpamAssassin ham: 4 150 писем, 0 `PHISHING`, 33 `SUSPICIOUS`;
- два последовательных запуска `deep` на benign-письме дали одинаковый структурированный результат и `NOT_DETECTED`;
- на RTX 4080 холодный deep-запуск занял около 12,1 с, повторный - 2,8 с, пик памяти - около 8,8 ГБ.

Это результаты на конкретных данных, а не обещание абсолютного нуля ошибок. PhreshPhish, MeAJOR, полный Enron и GovDocs1 в этот прогон не входили.

## Ограничения

- программа не может доказать, что письмо легитимно;
- особо опасные ссылки лучше проверять в отдельной VM;
- без полных SMTP-заголовков и DNS нельзя полностью проверить SPF/DKIM/DMARC;
- атака, которая становится вредоносной только после ручного диалога или авторизации, может потребовать проверки человеком;
- перед автоматической блокировкой у конкретного заказчика нужен прогон на его нормальной корпоративной почте.

