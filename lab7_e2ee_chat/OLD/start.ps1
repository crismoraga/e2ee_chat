# TEL252 Lab 7 - Launcher Script
# Inicia API y Web Client en terminales separadas automáticamente

Write-Host "🚀 Iniciando TEL252 Secure Chat..." -ForegroundColor Cyan

# Activar entorno virtual
if (Test-Path ".venv\Scripts\Activate.ps1") {
    & .\.venv\Scripts\Activate.ps1
}

# Limpiar datos anteriores (opcional)
$cleanup = Read-Host "¿Limpiar datos anteriores? (y/N)"
if ($cleanup -eq "y" -or $cleanup -eq "Y") {
    Remove-Item -Path "data\*.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "clients\state\*.json" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Datos limpiados" -ForegroundColor Green
}

# Iniciar API en nueva terminal
Write-Host "✓ Iniciando API Server en puerto 5000..." -ForegroundColor Yellow
$apiCmd = "cd '$PWD'; .\.venv\Scripts\Activate.ps1; python run_api.py"
Start-Process pwsh -ArgumentList "-NoExit", "-Command", $apiCmd

Start-Sleep -Seconds 2

# Iniciar Web Client en nueva terminal
Write-Host "✓ Iniciando Web Client en puerto 5001..." -ForegroundColor Yellow
Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$PWD'; .\.venv\Scripts\Activate.ps1; python clients/web_app.py"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "✅ Aplicación iniciada!" -ForegroundColor Green
Write-Host ""
Write-Host "  API:        http://127.0.0.1:5000/health" -ForegroundColor White
Write-Host "  Web Client: http://127.0.0.1:5001" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Abre tu navegador en: http://127.0.0.1:5001" -ForegroundColor Yellow
Write-Host ""
Write-Host "Para detener: Cierra las terminales nuevas o presiona Ctrl+C en ellas" -ForegroundColor Gray
Write-Host ""

# Abrir navegador automáticamente
Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:5001"
