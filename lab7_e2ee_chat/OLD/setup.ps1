# TEL252 Lab 7 - Quick Start Script
# Ejecuta este script para iniciar la API y el cliente web automáticamente

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  TEL252 Secure Chat E2EE - Lab 7 Quick Start  " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Verificar entorno virtual
if (!(Test-Path ".venv")) {
    Write-Host "[1/5] Creando entorno virtual..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "✓ Entorno virtual creado" -ForegroundColor Green
} else {
    Write-Host "[1/5] ✓ Entorno virtual ya existe" -ForegroundColor Green
}

# Activar entorno virtual
Write-Host "[2/5] Activando entorno virtual..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1
Write-Host "✓ Entorno activado" -ForegroundColor Green

# Instalar dependencias
Write-Host "[3/5] Instalando dependencias..." -ForegroundColor Yellow
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q
Write-Host "✓ Dependencias instaladas" -ForegroundColor Green

# Crear directorios necesarios
Write-Host "[4/5] Creando directorios..." -ForegroundColor Yellow
$directories = @("data", "clients\state", "certs")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
Write-Host "✓ Directorios creados" -ForegroundColor Green

# Ejecutar tests
Write-Host "[5/5] Ejecutando tests automatizados..." -ForegroundColor Yellow
python -m pytest tests/ -v --tb=short
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Tests passed!" -ForegroundColor Green
} else {
    Write-Host "✗ Tests failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Setup completo! Ahora puedes:" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Iniciar API (Terminal 1):" -ForegroundColor White
Write-Host "    python -m flask --app 'app.server:create_app()' run --port 5000" -ForegroundColor Gray
Write-Host ""
Write-Host "  Iniciar Web Client (Terminal 2):" -ForegroundColor White
Write-Host "    python clients/web_app.py" -ForegroundColor Gray
Write-Host ""
Write-Host "  Luego abre en tu navegador:" -ForegroundColor White
Write-Host "    http://127.0.0.1:5001" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Documentación completa:" -ForegroundColor White
Write-Host "    - Diagrama (50%): docs/sequence_diagram.md" -ForegroundColor Gray
Write-Host "    - Arquitectura: docs/architecture.md" -ForegroundColor Gray
Write-Host "    - Wireshark: docs/wireshark_guide.md" -ForegroundColor Gray
Write-Host "    - TLS: docs/deployment_guide.md" -ForegroundColor Gray
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
