# Скриншоты отчётов SAST/SCA

Файлы из этой папки подставляются в раздел
[«Скриншоты отчётов»](../../README.md#скриншоты-отчётов) основного README.

Что и откуда снимать (вкладка **Actions** репозитория
<https://github.com/PaulLocust/CS-lab1/actions/workflows/ci.yml>):

| Файл | Что должно быть на скриншоте | Где взять |
|---|---|---|
| `01-pipeline-success.png` | список job последнего запуска — все с зелёными галочками | страница запуска workflow «CI / Security» |
| `02-sast-spotbugs.png` | лог job «SAST — SpotBugs + FindSecBugs» со строками `BugInstance size is 0` и `BUILD SUCCESS` | раскрытый шаг «Статический анализ безопасности» |
| `03-sca-trivy.png` | вывод Trivy: уязвимостей HIGH/CRITICAL не найдено | шаг «Проверить зависимости на известные уязвимости» |
| `04-sca-dependency-check.png` | лог job «SCA — OWASP Dependency-Check» с `BUILD SUCCESS` | шаг «Проверить зависимости (OWASP Dependency-Check)». Красивее выглядит HTML-отчёт: скачать артефакт `dependency-check-report`, открыть `dependency-check-report.html` — либо получить его локально командой `./mvnw -Psecurity-scan verify` |
| `05-tests.png` | `Tests run: 39, Failures: 0, Errors: 0, Skipped: 0` | шаг «Прогнать тесты» в job «Сборка и автотесты» |
| `06-codeql.png` | job «SAST — CodeQL» завершился успешно | лог job либо вкладка Security → Code scanning |

Дополнительно (по желанию) — вкладка **Security → Code scanning**: туда в формате SARIF
загружаются результаты SpotBugs, Trivy и CodeQL.

Скриншоты именуйте ровно так, как указано в таблице, — тогда картинки в README подхватятся
без правок. Формат PNG, ширина примерно 1200–1600 px.
