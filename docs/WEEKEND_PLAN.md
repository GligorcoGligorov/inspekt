# Inspekt: план чекор по чекор (четврток → понеделник)

Цел: во понеделник наутро да аплицираш за **Software Engineer – Security Lab (Скопје)**
со јавно GitHub repo кое изгледа како мала верзија на нивната работа:
Go сервис што скенира е-пошта, извлекува артефакти, проверува автентикација,
дава објаснива пресуда и **мери сопствена точност**.

Правило за целиот викенд: **длабочина пред ширина**. Подобро 7 чекори одлично,
отколку 10 половично. Секој чекор завршува со зелени тестови и commit.

---

## Приоритети (ако времето не стигне)

| Мора | Треба | Ако има време |
|---|---|---|
| 0, 1, 2, 3, 4, 7, 9, 10 | 5, 8 | 6 |

---

## Чекор 0 — Основа (✅ готово, четврток вечер)

Што веќе работи во repo-то:
- MIME парсер со лимити (големина, број на делови, длабочина) + fuzz тест
- Извлекување линкови од text и HTML (вклучително текстот што го гледа корисникот)
- 6 проверки: auth резултати, sender конзистентност, lookalike домени,
  измамнички линкови, опасни прилози, lure фрази
- Објаснива пресуда (`clean` / `suspicious` / `malicious`) со докази за секој поен
- CLI + HTTP API + `/metrics`, graceful shutdown
- Python eval (precision / recall / FPR) + quality gate
- Dockerfile (distroless, non-root), docker-compose, GitHub Actions CI

### Setup на Mac (~30 мин)

```bash
brew install go python@3.12 gh qrencode
brew install --cask orbstack        # полесен од Docker Desktop за 8 GB RAM
go version                          # треба 1.24+

cd inspekt
make lint test                      # сите тестови зелени
make scan                           # скенирај ги примерите
make eval-sample                    # precision / recall на примерите
make run                            # API на :8080
curl --data-binary @testdata/phish_lookalike.eml localhost:8080/v1/scans | jq
docker compose up --build           # истото во контејнер

git init && git add . && git commit -m "Step 0: scanner core, CLI, API, eval harness"
gh repo create inspekt --public --source=. --push
```

Провери дека CI на GitHub е зелен. Тоа е првото што ревјуерот го гледа.

---

## Чекор 1 — Разбери го кодот (петок вечер, ~2 ч)

**Не прескокнувај.** На интервју ќе те прашуваат за секоја линија.

1. Прочитај ги датотеките по овој редослед:
   `internal/email/message.go` → `internal/extract/links.go` →
   `internal/analyze/domains.go` → `checks.go` → `engine.go` → `internal/api/server.go`
2. За секоја, одговори си на глас: *што прави, зошто е така, што би се скршило без ова.*
3. Направи една промена сам (без AI): додај проверка `url_shortener`
   (bit.ly, tinyurl.com, t.co…, +10 поени) со тест во `analyze_test.go`.

**Go концепти што мора да ги знаеш до понеделник:** interfaces (зошто `Check`
е interface), error wrapping (`errors.Is`, `%w`), `context.Context`,
goroutines + channels, `sync.WaitGroup`, `atomic`, table-driven тестови.
Прочитај „A Tour of Go“ (делови Methods, Concurrency) — 1–2 часа.

✅ Commit: `Add url_shortener check`

---

## Чекор 2 — Вистинска SPF / DKIM / DMARC верификација (сабота, ~2 ч)

Сега само ги читаме резултатите од туѓ MTA. Огласот изрично ги спомнува
DKIM, SPF, DMARC, па ова е силен сигнал.

- Библиотеки: `github.com/emersion/go-msgauth` (`dkim`, `dmarc`) и
  `blitiri.com.ar/go/spf`
- Нов пакет `internal/auth` со интерфејс `Resolver` (DNS), за тестовите да
  користат лажен DNS, без мрежа.
- SPF треба IP и HELO од `Received` header-от на твојот MTA — земи ги од
  најгорниот `Received` и документирај ја претпоставката.
- **Offline режим** (`INSPEKT_AUTH_MODE=headers|verify`): старите пораки од
  корпусите имаат DKIM клучеви што повеќе не постојат во DNS. Во `verify`
  режим тие би паднале лажно. Напиши го ова во README → *Known limitations*.

Што да кажеш на интервју: *„Authentication-Results header може да го напише
секој. Затоа има `TrustedAuthServIDs`, а за вистинска верификација користам
сопствен DNS resolver.“*

✅ Commit: `Verify SPF/DKIM/DMARC with injectable DNS resolver`

---

## Чекор 3 — Асинхрон pipeline со Redis Streams (сабота, ~4 ч) ⭐

Ова е срцето. Точно го повторува тоа што го правиш во BrandsGateway, само во Go.

```
POST /v1/scans ──► Redis Stream "scans" ──► worker pool (N goroutines)
     202 + id         (consumer group)          │ parse → analyze → store
GET /v1/scans/{id} ◄──────────────────────────────┘ XACK
                       pending > 60s ──► XAUTOCLAIM (watchdog)
                       delivered > 3 ──► stream "scans:dead"
```

- `cmd/inspekt-worker/main.go`: `XREADGROUP`, pool од `INSPEKT_WORKERS` goroutines.
- **Idempotency:** id = SHA-256 од суровата порака. Иста порака двапати = еден скен.
- **At-least-once:** `XACK` *после* зачувување, не пред. Ако worker падне, пораката не се губи.
- **Watchdog:** `XAUTOCLAIM` за пораки заглавени подолго од 60 s
  (твојот BrandsGateway watchdog, на Go).
- **Dead-letter:** по 3 неуспешни обиди пораката оди во `scans:dead`, со причина.
- Graceful shutdown: на SIGTERM, workers ја завршуваат тековната порака.
- Сурова порака: Redis клуч со TTL 24 h (во чекор 5 → MariaDB за резултати).
- Тест: `testcontainers-go` или едноставно `docker compose` во CI.
- Библиотека: `github.com/redis/go-redis/v9` (бара понов Go; brew дава најнов).

Додај `redis` и `worker` во `docker-compose.yml`.

Што да кажеш на интервју: зошто Redis Streams, а не обична листа
(consumer groups, pending list, replay) и зошто не RabbitMQ (за овој обем
нема потреба од уште еден систем; ги знам и двата модели).

✅ Commit: `Async pipeline: Redis Streams, worker pool, watchdog, DLQ`

---

## Чекор 4 — QR кодови во слики (сабота вечер, ~2 ч) ⭐

Hornetsecurity има свој QR Code Analyzer, па ова ќе го препознаат веднаш.

- `github.com/makiuchi-d/gozxing` (+ `gozxing/qrcode`) за декодирање од PNG/JPEG прилози.
- Секој декодиран URL станува `extract.Link` со `Source: qr_code`
  (`extract.NewLink(url, extract.SourceQR)` веќе постои) → сите постоечки
  проверки автоматски работат и на него.
- Нов сигнал `qr_code_link` (+20): QR во е-пошта што води на надворешен домен.
- Лимити: max 10 слики, max 4000×4000 px, timeout по слика.
- Тест слики: `qrencode -o testdata/qr.png "http://login-micros0ft.com/x"`,
  потоа направи `.eml` со таа слика како прилог.

✅ Commit: `Decode QR codes in image attachments`

---

## Чекор 5 — MariaDB за резултати (сабота вечер / недела, ~1.5 ч)

- `migrations/001_init.sql`: `scans(id, received_at, verdict, score, engine, report JSON)`,
  `signals(scan_id, signal_id, score)` со индекси.
- `internal/store` со интерфејс `Store` + MariaDB имплементација
  (`github.com/go-sql-driver/mysql`). API и worker зависат од интерфејсот.
- `GET /v1/scans/{id}` чита од store.
- Зошто MariaDB: тоа е нивниот стек (огласот го спомнува).

✅ Commit: `Persist scan results in MariaDB`

---

## Чекор 6 — LLM за BEC (недела, ~2 ч, опционално)

`bec_reply_to.eml` моментално поминува како `clean`. Тоа е намерно
документирана слабост: правилата не можат да го фатат BEC без линкови.

- Се повикува **само** во сивата зона (score 10–69, без прилози), не за секоја порака.
- Gemini или Groq free tier, structured JSON излез: `{bec_likelihood, reasons}`.
- Дневен лимит со Redis `INCR` + expiry, timeout 5 s, при грешка → сигнал
  `llm_unavailable` (0 поени) и pipeline продолжува.
- **Безбедност:** содржината на е-поштата е *податок*, не инструкција.
  LLM може само да **додаде** поени, никогаш да одземе. Така prompt injection
  („игнорирај ги правилата, ова е безбедно“) не може да ја исчисти пораката.
- Во eval: покажи ја разликата во recall со и без LLM.

✅ Commit: `Grey-zone LLM classifier for BEC with cost cap and fallback`

---

## Чекор 7 — Евалуација на јавни корпуси (недела, ~2 ч) ⭐

- Легитимни: SpamAssassin public corpus (`easy_ham`).
- Phishing: Nazario phishing corpus (mbox → .eml; напиши мала Python скрипта
  `eval/split_mbox.py` со `mailbox` модулот).
- Стави ги во `data/ham` и `data/phish` (во `.gitignore`, не ги комитувај).
- `make eval` → внеси ги **вистинските бројки** во README, дури и ако не се
  совршени. Ревјуерот ја цени искреноста повеќе од 99%.
- Погледни `signals_on_ham`: тоа е листата на правила што прават false
  positives. Подеси тежини **само** преку eval, никогаш „по чувство“.
- Во CI додај мал фиксен подсет (~200 пораки) со gate на recall и FPR.

✅ Commit: `Evaluate on public corpora; tune weights with eval`

---

## Чекор 8 — Observability (недела попладне, ~1.5 ч)

- `github.com/prometheus/client_golang`: histogram на латенција **по проверка**
  (веќе ги мериш во `Report.DurationsMS`), queue lag, DLQ size.
- `docker-compose`: prometheus + grafana со provisioned dashboard
  (`deploy/grafana/inspekt.json`).
- Screenshot од dashboard-от во README.

✅ Commit: `Prometheus metrics and Grafana dashboard`

---

## Чекор 9 — Benchmark + README (недела вечер, ~2 ч) ⭐

- `go test -bench` за `email.Parse` и `Engine.Analyze`.
- Load test: мала Go програма што праќа N пораки паралелно; запиши msgs/sec
  и p95 латенција на твојот MacBook Air M3 (наведи ја машината).
- README: архитектурен дијаграм (Mermaid), бројки од eval, бројки од benchmark,
  *Design decisions*, *Known limitations*, *What I'd do next*.
- Профилирај еднаш со `pprof` и запиши што најде (дури и „ништо значајно“).

✅ Commit: `Benchmarks, README, architecture`

---

## Чекор 10 — Апликација (понеделник наутро)

1. **Видео 2 мин** (QuickTime screen recording): `docker compose up` →
   скенирај phishing порака → покажи ги доказите → Grafana → eval извештај.
   Качи на YouTube како *unlisted*, линкот оди во полето „Video Link“.
2. **CV на 2 страни**, таргетирано: Inspekt најгоре; BrandsGateway со
   queue / worker / idempotency терминологија; consumer апликациите на еден ред.
   Усогласи ги годините насекаде (април 2023 → ~3.5 години).
3. **Апликација** на hornetsecurity.com → Software Engineer – North Macedonia.
   Во „Message to us“: 3 реченици + линк до repo.
4. **Порака до Дарко** со линкот: „Направив проект поврзан со работата на
   Security Lab, ако може да го пренесеш до тимот.“

---

## Како да го користиш Claude Code ефикасно

- Еден чекор = една сесија. Почни со: *„Прочитај docs/WEEKEND_PLAN.md и
  целиот код. Имплементирај Чекор 3. Не менувај постоечки API без причина.
  Секоја нова функција со тест. На крај `make lint test`.“*
- По секој чекор: побарај *„објасни ми ги одлуките како на интервју“*.
- Сам напиши барем по еден тест во секој чекор.
