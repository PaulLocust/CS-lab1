<#
    Проверка API из PowerShell (совместимо с Windows PowerShell 5.1 и PowerShell 7+).

    Запуск:  powershell -ExecutionPolicy Bypass -File scripts\smoke-test.ps1
    Параметр: -BaseUrl http://localhost:8080
#>
param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$AdminUser = "admin",
    [string]$AdminPassword = "Admin#Str0ng-2026",
    [string]$UserName = "alice",
    [string]$UserPassword = "Alice#Str0ng-2026"
)

$ErrorActionPreference = "Continue"

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title" -ForegroundColor Cyan
}

# Единая обёртка: возвращает код ответа и тело даже для 4xx/5xx.
function Invoke-Api {
    param(
        [string]$Method = "GET",
        [string]$Path,
        [string]$Token,
        [hashtable]$Body
    )

    $headers = @{}
    if ($Token) { $headers["Authorization"] = "Bearer $Token" }

    $params = @{
        Uri             = "$BaseUrl$Path"
        Method          = $Method
        Headers         = $headers
        UseBasicParsing = $true
    }
    if ($Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Compress)
        $params["ContentType"] = "application/json; charset=utf-8"
    }

    try {
        $response = Invoke-WebRequest @params
        # Тело читаем из потока и декодируем как UTF-8: Windows PowerShell 5.1 иначе
        # интерпретирует ответ без charset в Content-Type как ISO-8859-1 и портит кириллицу.
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content    = [System.Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
            Headers    = $response.Headers
        }
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($null -eq $webResponse) { throw }

        $stream = $webResponse.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        $content = $reader.ReadToEnd()
        $reader.Dispose()

        return [pscustomobject]@{
            StatusCode = [int]$webResponse.StatusCode
            Content    = $content
            Headers    = $webResponse.Headers
        }
    }
}

Write-Section "1. Health check"
(Invoke-Api -Path "/actuator/health").Content

Write-Section "2. POST /auth/login"
$loginResponse = Invoke-Api -Method POST -Path "/auth/login" -Body @{ username = $UserName; password = $UserPassword }
Write-Host "HTTP $($loginResponse.StatusCode)"
$token = ($loginResponse.Content | ConvertFrom-Json).accessToken
Write-Host "Длина токена: $($token.Length)"

Write-Section "3. GET /api/data без токена (ожидаем 401)"
Write-Host "HTTP $((Invoke-Api -Path '/api/data').StatusCode)"

Write-Section "4. GET /api/data с токеном (ожидаем 200)"
$data = Invoke-Api -Path "/api/data?page=0&size=3" -Token $token
Write-Host "HTTP $($data.StatusCode)"
$data.Content

Write-Section "5. POST /api/data с XSS-payload и кириллицей"
$created = Invoke-Api -Method POST -Path "/api/data" -Token $token -Body @{
    title   = "XSS <script>alert('pwned')</script> Проверка"
    content = "<img src=x onerror=alert(1)> Обычный текст & спецсимволы"
}
Write-Host "HTTP $($created.StatusCode)"
$created.Content

Write-Section "6. SQL-инъекция в поиске (ожидаем пустой результат и целую таблицу)"
$injection = [uri]::EscapeDataString("' OR '1'='1")
$search = Invoke-Api -Path "/api/data/search?query=$injection" -Token $token
Write-Host "HTTP $($search.StatusCode): $($search.Content)"

$dropTable = [uri]::EscapeDataString("x'; DROP TABLE posts; --")
Write-Host "DROP TABLE -> HTTP $((Invoke-Api -Path "/api/data/search?query=$dropTable" -Token $token).StatusCode)"
Write-Host "данные на месте -> HTTP $((Invoke-Api -Path '/api/data' -Token $token).StatusCode)"

Write-Section "7. GET /api/users: пользователь (403) и администратор (200)"
Write-Host "alice -> HTTP $((Invoke-Api -Path '/api/users' -Token $token).StatusCode)"
$adminToken = ((Invoke-Api -Method POST -Path "/auth/login" -Body @{ username = $AdminUser; password = $AdminPassword }).Content | ConvertFrom-Json).accessToken
Write-Host "admin -> HTTP $((Invoke-Api -Path '/api/users' -Token $adminToken).StatusCode)"

Write-Section "8. Подделанный токен (ожидаем 401)"
$tampered = $token.Substring(0, $token.Length - 2) + "AA"
Write-Host "HTTP $((Invoke-Api -Path '/api/data' -Token $tampered).StatusCode)"

Write-Section "9. Защитные HTTP-заголовки"
$responseHeaders = (Invoke-Api -Path "/api/data" -Token $token).Headers
foreach ($name in @("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy")) {
    $value = $responseHeaders[$name]
    if ($value) { Write-Host "$name : $value" }
}

Write-Section "10. Brute-force: 6 попыток подряд (ожидаем 429 в конце)"
foreach ($i in 1..6) {
    $response = Invoke-Api -Method POST -Path "/auth/login" -Body @{ username = "brute.target"; password = "WrongPassword#$i" }
    Write-Host "попытка $i -> HTTP $($response.StatusCode)"
}

Write-Host ""
Write-Host "Готово." -ForegroundColor Green
