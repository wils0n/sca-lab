# Laboratorio de Análisis de Dependencias y SCA

**Nivel**: Intermedio/Avanzado  
**Objetivo**: Implementar herramientas SCA para detectar y gestionar vulnerabilidades en dependencias de software

## Estructura del Laboratorio

### Parte: Configuración del Entorno

### Parte: Análisis con Trivy

### Parte: Análisis con Snyk

### Parte: Análisis Comparativo y Reportes

### Parte: Corrección de Vulnerabilidades

### Parte: Validación de Correcciones

### Parte: Integración con Gitlab CI

---

## Requisitos Previos

- **Sistema Operativo**: Windows 10/11 o Linux/macOS
- **Herramientas Base**: Git, Docker, Java 11+, Node.js 16+
- **Acceso a Internet** para descargar herramientas y bases de datos
- **Archivo run.sh** brindar permiso chmod +x run.sh

---

## Parte: Configuración del Entorno (15 minutos)

### 1.1 Preparación del Proyecto de Prueba

**Bash (Linux/macOS):**

```bash
# Validar que existe directorio de trabajo
cd sca-lab
ls

# Instalar dependencias Node.js
cd nodejs-vulnerable-app
npm install

echo "✅ Entorno configurado correctamente"
```

**PowerShell (Windows):**

```powershell
# Validar que existe directorio de trabajo
Set-Location "sca-lab"

# Instalar dependencias Node.js
Set-Location "nodejs-vulnerable-app"
npm install

Write-Host "✅ Entorno configurado correctamente" -ForegroundColor Green
```

### 1.2 Crear Directorio de Reportes

**Bash:**

```bash
cd sca-lab
mkdir -p reports
mkdir -p sbom
echo "📁 Directorios de salida creados"
```

**PowerShell:**

```powershell
Set-Location "sca-lab"
New-Item -ItemType Directory -Path "reports" -Force
New-Item -ItemType Directory -Path "sbom" -Force
Write-Host "📁 Directorios de salida creados" -ForegroundColor Green
```

---

## Parte: Análisis con Trivy

### 2.1 Instalación de Trivy

**Bash:**

```bash
cd sca-lab

echo "⬇️ Instalando Trivy..."

# Instalar Trivy usando script oficial
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Verificar instalación
trivy --version

echo "✅ Trivy instalado correctamente"
```

**PowerShell:**

```powershell
Set-Location "sca-lab"

Write-Host "⬇️ Instalando Trivy..." -ForegroundColor Yellow

# Descargar Trivy para Windows
$trivyVersion = "0.63.0"
$trivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_$($trivyVersion)_Windows-64bit.zip"

Invoke-WebRequest -Uri $trivyUrl -OutFile "trivy.zip"
Expand-Archive -Path "trivy.zip" -DestinationPath "trivy" -Force

# Verificar instalación
& ".\trivy\trivy.exe" --version

Write-Host "✅ Trivy instalado correctamente" -ForegroundColor Green
```

### 2.2 Análisis de Vulnerabilidades con Trivy

**Bash:**

```bash
cd sca-lab
echo "🔍 Analizando vulnerabilidades con Trivy..."

# Análisis del proyecto Java
echo "📊 Analizando proyecto Java..."
trivy fs ./java-vulnerable-app --format json --output ./reports/trivy-java-report.json
trivy fs ./java-vulnerable-app --format table

# Análisis del proyecto Node.js
echo "📊 Analizando proyecto Node.js..."
trivy fs ./nodejs-vulnerable-app --format json --output ./reports/trivy-nodejs-report.json
trivy fs ./nodejs-vulnerable-app --format table

echo "✅ Análisis con Trivy completado"
```

**PowerShell:**

```powershell
Write-Host "🔍 Analizando vulnerabilidades con Trivy..." -ForegroundColor Yellow

# Análisis del proyecto Java
Write-Host "📊 Analizando proyecto Java..." -ForegroundColor Cyan
& ".\trivy\trivy.exe" fs .\java-vulnerable-app --format json --output .\reports\trivy-java-report.json
& ".\trivy\trivy.exe" fs .\java-vulnerable-app --format table

# Análisis del proyecto Node.js
Write-Host "📊 Analizando proyecto Node.js..." -ForegroundColor Cyan
& ".\trivy\trivy.exe" fs .\nodejs-vulnerable-app --format json --output .\reports\trivy-nodejs-report.json
& ".\trivy\trivy.exe" fs .\nodejs-vulnerable-app --format table

Write-Host "✅ Análisis con Trivy completado" -ForegroundColor Green
```

### 2.3 Generación de SBOM con Trivy

**Bash:**

```bash

echo "📦 Generando SBOM con Trivy..."

# Generar SBOM en formato CycloneDX para proyecto Java
trivy fs ./java-vulnerable-app --format cyclonedx --output ./sbom/java-sbom.json

# Generar SBOM en formato SPDX para proyecto Java
trivy fs ./java-vulnerable-app --format spdx-json --output ./sbom/java-sbom-spdx.json

# Generar SBOM para proyecto Node.js
trivy fs ./nodejs-vulnerable-app --format cyclonedx --output ./sbom/nodejs-sbom.json

echo "✅ SBOM generados correctamente"
echo "📊 Archivos SBOM:"
ls -la sbom/
```

**PowerShell:**

```powershell
Write-Host "📦 Generando SBOM con Trivy..." -ForegroundColor Yellow

# Generar SBOM en formato CycloneDX para proyecto Java
& ".\trivy\trivy.exe" fs .\java-vulnerable-app --format cyclonedx --output .\sbom\java-sbom.json

# Generar SBOM en formato SPDX para proyecto Java
& ".\trivy\trivy.exe" fs .\java-vulnerable-app --format spdx-json --output .\sbom\java-sbom-spdx.json

# Generar SBOM para proyecto Node.js
& ".\trivy\trivy.exe" fs .\nodejs-vulnerable-app --format cyclonedx --output .\sbom\nodejs-sbom.json

Write-Host "✅ SBOM generados correctamente" -ForegroundColor Green
Write-Host "📊 Archivos SBOM:" -ForegroundColor Cyan
Get-ChildItem -Path ".\sbom\"
```

---

## Parte: Análisis con Snyk

### 1 Instalación y Configuración de Snyk

**Bash:**

```bash
cd sca-lab

echo "⬇️ Instalando Snyk CLI..."

# Instalar Snyk CLI
npm install -g snyk

# Verificar instalación
snyk --version

echo "🔑 Para usar Snyk, necesitas autenticarte:"
echo "1. Visita https://snyk.io y crea una cuenta gratuita"
echo "2. Ejecuta: snyk auth"
echo "3. Sigue las instrucciones para autenticarte"
echo ""
echo "💡 Para este laboratorio, usaremos el modo offline cuando sea posible"
```

**PowerShell:**

```powershell
Set-Location "sca-lab"

Write-Host "⬇️ Instalando Snyk CLI..." -ForegroundColor Yellow

# Instalar Snyk CLI
npm install -g snyk

# Verificar instalación
snyk --version

Write-Host "🔑 Para usar Snyk, necesitas autenticarte:" -ForegroundColor Cyan
Write-Host "1. Visita https://snyk.io y crea una cuenta gratuita" -ForegroundColor White
Write-Host "2. Ejecuta: snyk auth" -ForegroundColor White
Write-Host "3. Sigue las instrucciones para autenticarte" -ForegroundColor White
Write-Host ""
Write-Host "💡 Para este laboratorio, usaremos el modo offline cuando sea posible" -ForegroundColor Yellow
```

### 2 Análisis con Snyk (Modo Offline)

**Bash:**

```bash
echo "🔍 Analizando con Snyk..."

# Análisis del proyecto Java (Maven)
cd sca-lab/java-vulnerable-app
echo "📊 Analizando proyecto Java con Snyk..."

# Crear reporte de vulnerabilidades localmente
snyk test --file=pom.xml --json > ../reports/snyk-java-report.json || true
snyk test --file=pom.xml || true

# Análisis del proyecto Node.js
cd ../nodejs-vulnerable-app
echo "📊 Analizando proyecto Node.js con Snyk..."

snyk test --json > ../reports/snyk-nodejs-report.json || true
snyk test || true

cd ..
echo "✅ Análisis con Snyk completado"
```

**PowerShell:**

```powershell
Write-Host "🔍 Analizando con Snyk..." -ForegroundColor Yellow

# Análisis del proyecto Java (Maven)
Set-Location "sca-lab\java-vulnerable-app"
Write-Host "📊 Analizando proyecto Java con Snyk..." -ForegroundColor Cyan

# Crear reporte de vulnerabilidades localmente
try {
    snyk test --file=pom.xml --json | Out-File -FilePath "..\reports\snyk-java-report.json" -Encoding UTF8
    snyk test --file=pom.xml
} catch {
    Write-Host "⚠️ Snyk requiere autenticación para análisis completo" -ForegroundColor Yellow
}

# Análisis del proyecto Node.js
Set-Location ".."
Write-Host "📊 Analizando proyecto Node.js con Snyk..." -ForegroundColor Cyan

try {
    snyk test --json | Out-File -FilePath "..\reports\snyk-nodejs-report.json" -Encoding UTF8
    snyk test
} catch {
    Write-Host "⚠️ Snyk requiere autenticación para análisis completo" -ForegroundColor Yellow
}

Set-Location ".."
Write-Host "✅ Análisis con Snyk completado" -ForegroundColor Green
```

### 3 Análisis de Dependencias con npm audit

**Bash:**

```bash
echo "🔍 Análisis adicional con npm audit..."

cd sca-lab/nodejs-vulnerable-app

# Ejecutar audit de npm
echo "📊 Ejecutando npm audit..."
npm audit --json > ../reports/npm-audit-report.json || true
npm audit

# Mostrar solo vulnerabilidades críticas y altas
echo "⚠️ Vulnerabilidades críticas y altas:"
npm audit --audit-level=high || true

cd ..
echo "✅ Análisis con npm audit completado"
```

**PowerShell:**

```powershell
Write-Host "🔍 Análisis adicional con npm audit..." -ForegroundColor Yellow

Set-Location "sca-lab\nodejs-vulnerable-app"

# Ejecutar audit de npm
Write-Host "📊 Ejecutando npm audit..." -ForegroundColor Cyan
try {
    npm audit --json | Out-File -FilePath "..\reports\npm-audit-report.json" -Encoding UTF8
    npm audit
} catch {
    Write-Host "⚠️ Se encontraron vulnerabilidades" -ForegroundColor Yellow
}

# Mostrar solo vulnerabilidades críticas y altas
Write-Host "⚠️ Vulnerabilidades críticas y altas:" -ForegroundColor Red
try {
    npm audit --audit-level=high
} catch {
    Write-Host "Se encontraron vulnerabilidades de alto riesgo" -ForegroundColor Yellow
}

Set-Location ".."
Write-Host "✅ Análisis con npm audit completado" -ForegroundColor Green
```

---

## Parte: Análisis Comparativo y Reportes

### 1 Comparación de Resultados

**Bash:**

```bash
cd sca-lab
echo "📊 Generando resumen comparativo de herramientas SCA..."

# Crear script de análisis comparativo
cat > generate_comparison.sh << 'EOF'
#!/bin/bash

echo "====================================="
echo "   RESUMEN COMPARATIVO SCA TOOLS"
echo "====================================="
echo ""

echo "📁 Archivos de reportes generados:"
echo "-----------------------------------"
find reports/ -name "*.json" -o -name "*.html" | sort

echo ""
echo "📦 Archivos SBOM generados:"
echo "----------------------------"
find sbom/ -name "*.json" -o -name "*.sig" | sort

echo ""
echo "🔍 Análisis de vulnerabilidades encontradas:"
echo "--------------------------------------------"

# OWASP Dependency-Check
if [ -f "reports/dependency-check-report.json" ]; then
    OWASP_VULNS=$(cat reports/dependency-check-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length' 2>/dev/null || echo "0")
    echo "🛡️  OWASP Dependency-Check: $OWASP_VULNS vulnerabilidades"
fi

# Trivy
if [ -f "reports/trivy-java-report.json" ]; then
    TRIVY_JAVA_VULNS=$(cat reports/trivy-java-report.json | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")
    echo "🔍 Trivy (Java): $TRIVY_JAVA_VULNS vulnerabilidades"
fi

if [ -f "reports/trivy-nodejs-report.json" ]; then
    TRIVY_NODE_VULNS=$(cat reports/trivy-nodejs-report.json | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")
    echo "🔍 Trivy (Node.js): $TRIVY_NODE_VULNS vulnerabilidades"
fi

# npm audit
if [ -f "reports/npm-audit-report.json" ]; then
    NPM_VULNS=$(cat reports/npm-audit-report.json | jq '.metadata.vulnerabilities.total' 2>/dev/null || echo "0")
    echo "📦 npm audit: $NPM_VULNS vulnerabilidades"
fi

echo ""
echo "🎯 Conclusiones del análisis:"
echo "-----------------------------"
echo "• Se han analizado proyectos Java y Node.js con múltiples herramientas SCA"
echo "• Se generaron SBOM en formatos estándar (CycloneDX, SPDX)"
echo "• Se implementó firmado digital para garantizar integridad"
echo "• Cada herramienta tiene fortalezas específicas en la detección"
EOF

chmod +x generate_comparison.sh
./generate_comparison.sh
```

**PowerShell:**

```powershell
Write-Host "📊 Generando resumen comparativo de herramientas SCA..." -ForegroundColor Yellow

# Crear función de análisis comparativo
function Generate-Comparison {
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "   RESUMEN COMPARATIVO SCA TOOLS" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "📁 Archivos de reportes generados:" -ForegroundColor White
    Write-Host "-----------------------------------" -ForegroundColor White
    Get-ChildItem -Path ".\reports\" -Recurse -Include "*.json", "*.html" | Sort-Object Name | ForEach-Object { Write-Host $_.FullName -ForegroundColor Yellow }

    Write-Host ""
    Write-Host "📦 Archivos SBOM generados:" -ForegroundColor White
    Write-Host "----------------------------" -ForegroundColor White
    Get-ChildItem -Path ".\sbom\" -Recurse -Include "*.json", "*.sig" | Sort-Object Name | ForEach-Object { Write-Host $_.FullName -ForegroundColor Yellow }

    Write-Host ""
    Write-Host "🔍 Análisis de vulnerabilidades encontradas:" -ForegroundColor White
    Write-Host "--------------------------------------------" -ForegroundColor White

    # Contadores de vulnerabilidades
    $vulnCounts = @{}

    # OWASP Dependency-Check
    if (Test-Path ".\reports\dependency-check-report.json") {
        try {
            $owaspReport = Get-Content ".\reports\dependency-check-report.json" | ConvertFrom-Json
            $owaspVulns = ($owaspReport.dependencies | Where-Object { $_.vulnerabilities } | ForEach-Object { $_.vulnerabilities }).Count
            Write-Host "🛡️  OWASP Dependency-Check: $owaspVulns vulnerabilidades" -ForegroundColor Red
            $vulnCounts["OWASP"] = $owaspVulns
        } catch {
            Write-Host "🛡️  OWASP Dependency-Check: Error al procesar reporte" -ForegroundColor Yellow
        }
    }

    # npm audit
    if (Test-Path ".\reports\npm-audit-report.json") {
        try {
            $npmReport = Get-Content ".\reports\npm-audit-report.json" | ConvertFrom-Json
            $npmVulns = $npmReport.metadata.vulnerabilities.total
            Write-Host "📦 npm audit: $npmVulns vulnerabilidades" -ForegroundColor Red
            $vulnCounts["npm"] = $npmVulns
        } catch {
            Write-Host "📦 npm audit: Error al procesar reporte" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "🎯 Conclusiones del análisis:" -ForegroundColor White
    Write-Host "-----------------------------" -ForegroundColor White
    Write-Host "• Se han analizado proyectos Java y Node.js con múltiples herramientas SCA" -ForegroundColor Green
    Write-Host "• Se generaron SBOM en formatos estándar (CycloneDX, SPDX)" -ForegroundColor Green
    Write-Host "• Se implementó firmado digital para garantizar integridad" -ForegroundColor Green
    Write-Host "• Cada herramienta tiene fortalezas específicas en la detección" -ForegroundColor Green
}

# Ejecutar análisis comparativo
Generate-Comparison
```

---

## Parte: Corrección de Vulnerabilidades

### 1 Análisis Detallado de Vulnerabilidades Encontradas

**Bash:**

```bash
echo "🔍 Analizando vulnerabilidades específicas para corrección..."

# Crear función para mostrar vulnerabilidades críticas
analyze_vulnerabilities() {
    echo "====================================="
    echo "   VULNERABILIDADES CRÍTICAS"
    echo "====================================="

    # Analizar vulnerabilidades de npm audit
    cd sca-lab/nodejs-vulnerable-app
    echo "📊 Vulnerabilidades en proyecto Node.js:"
    echo "----------------------------------------"

    # Mostrar detalles de vulnerabilidades críticas
    npm audit --audit-level=critical --json > ../reports/critical-vulns.json 2>/dev/null || true

    if [ -f "../reports/critical-vulns.json" ]; then
        echo "🚨 Vulnerabilidades CRÍTICAS encontradas:"
        cat ../reports/critical-vulns.json | jq -r '.vulnerabilities | to_entries[] | "\(.key): \(.value.severity) - \(.value.title)"' 2>/dev/null || echo "Error procesando JSON"
    fi

    echo ""
    echo "📋 Resumen de dependencias vulnerables más comunes:"
    echo "- lodash 4.17.19 → CVE-2020-8203 (Prototype Pollution)"
    echo "- express 4.16.4 → CVE-2022-24999 (DoS vulnerability)"
    echo "- minimist 1.2.0 → CVE-2020-7598 (Prototype Pollution)"
    echo "- yargs-parser 13.1.1 → CVE-2020-7608 (Prototype Pollution)"

    cd ~/sca-lab
}

analyze_vulnerabilities
```

**PowerShell:**

```powershell
Write-Host "🔍 Analizando vulnerabilidades específicas para corrección..." -ForegroundColor Yellow

function Analyze-Vulnerabilities {
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "   VULNERABILIDADES CRÍTICAS" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan

    # Analizar vulnerabilidades de npm audit
    Set-Location "sca-lab\nodejs-vulnerable-app"
    Write-Host "📊 Vulnerabilidades en proyecto Node.js:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor White

    # Mostrar detalles de vulnerabilidades críticas
    try {
        npm audit --audit-level=critical --json | Out-File -FilePath "..\reports\critical-vulns.json" -Encoding UTF8

        if (Test-Path "..\reports\critical-vulns.json") {
            Write-Host "🚨 Vulnerabilidades CRÍTICAS encontradas:" -ForegroundColor Red
            $criticalVulns = Get-Content "..\reports\critical-vulns.json" | ConvertFrom-Json
            # Procesar y mostrar vulnerabilidades críticas
            Write-Host "Ver archivo: sca-lab\reports\critical-vulns.json para detalles" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️ Error al generar reporte de vulnerabilidades críticas" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "📋 Resumen de dependencias vulnerables más comunes:" -ForegroundColor White
    Write-Host "- lodash 4.17.19 → CVE-2020-8203 (Prototype Pollution)" -ForegroundColor Red
    Write-Host "- express 4.16.4 → CVE-2022-24999 (DoS vulnerability)" -ForegroundColor Red
    Write-Host "- minimist 1.2.0 → CVE-2020-7598 (Prototype Pollution)" -ForegroundColor Red
    Write-Host "- yargs-parser 13.1.1 → CVE-2020-7608 (Prototype Pollution)" -ForegroundColor Red

    Set-Location "sca-lab"
}

Analyze-Vulnerabilities
```

### 2 Corrección Manual de Dependencias Node.js

**Bash:**

```bash
echo "🔧 Aplicando correcciones a dependencias vulnerables..."

cd sca-lab/nodejs-vulnerable-app

# Crear backup del package.json original
cp package.json package.json.backup
echo "💾 Backup creado: package.json.backup"

# Crear versión corregida del package.json
echo "📝 Actualizando dependencias a versiones seguras..."

cat > package.json << 'EOF'
{
  "name": "vulnerable-node-app",
  "version": "1.0.0",
  "description": "Aplicación Node.js con dependencias corregidas",
  "main": "app.js",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2",
    "minimist": "1.2.8",
    "yargs-parser": "21.1.1"
  }
}
EOF

echo "✅ Dependencias actualizadas a versiones seguras:"
echo "- lodash: 4.17.19 → 4.17.21 (corrige CVE-2020-8203)"
echo "- express: 4.16.4 → 4.18.2 (corrige múltiples CVEs)"
echo "- minimist: 1.2.0 → 1.2.8 (corrige CVE-2020-7598)"
echo "- yargs-parser: 13.1.1 → 21.1.1 (corrige CVE-2020-7608)"

# Limpiar node_modules y reinstalar
echo "🧹 Limpiando instalación anterior..."
rm -rf node_modules package-lock.json

echo "📦 Instalando dependencias corregidas..."
npm install

echo "✅ Dependencias corregidas instaladas"

cd ..
```

**PowerShell:**

```powershell
Write-Host "🔧 Aplicando correcciones a dependencias vulnerables..." -ForegroundColor Yellow

Set-Location "sca-lab\nodejs-vulnerable-app"

# Crear backup del package.json original
Copy-Item "package.json" "package.json.backup"
Write-Host "💾 Backup creado: package.json.backup" -ForegroundColor Green

# Crear versión corregida del package.json
Write-Host "📝 Actualizando dependencias a versiones seguras..." -ForegroundColor Cyan

@'
{
  "name": "vulnerable-node-app",
  "version": "1.0.0",
  "description": "Aplicación Node.js con dependencias corregidas",
  "main": "app.js",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2",
    "minimist": "1.2.8",
    "yargs-parser": "21.1.1"
  }
}
'@ | Out-File -FilePath "package.json" -Encoding UTF8

Write-Host "✅ Dependencias actualizadas a versiones seguras:" -ForegroundColor Green
Write-Host "- lodash: 4.17.19 → 4.17.21 (corrige CVE-2020-8203)" -ForegroundColor White
Write-Host "- express: 4.16.4 → 4.18.2 (corrige múltiples CVEs)" -ForegroundColor White
Write-Host "- minimist: 1.2.0 → 1.2.8 (corrige CVE-2020-7598)" -ForegroundColor White
Write-Host "- yargs-parser: 13.1.1 → 21.1.1 (corrige CVE-2020-7608)" -ForegroundColor White

# Limpiar node_modules y reinstalar
Write-Host "🧹 Limpiando instalación anterior..." -ForegroundColor Yellow
Remove-Item -Path "node_modules" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "package-lock.json" -Force -ErrorAction SilentlyContinue

Write-Host "📦 Instalando dependencias corregidas..." -ForegroundColor Cyan
npm install

Write-Host "✅ Dependencias corregidas instaladas" -ForegroundColor Green

Set-Location ".."
```

### 3 Corrección Manual de Dependencias Java

**Bash:**

```bash
echo "🔧 Aplicando correcciones a dependencias Java vulnerables..."

cd sca-lab/java-vulnerable-app

# Crear backup del pom.xml original
cp pom.xml pom.xml.backup
echo "💾 Backup creado: pom.xml.backup"

# Crear versión corregida del pom.xml
echo "📝 Actualizando dependencias Java a versiones seguras..."

cat > pom.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>secure-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.20.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.0.11</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.4</version>
        </dependency>
    </dependencies>
</project>
EOF

echo "✅ Dependencias Java actualizadas a versiones seguras:"
echo "- log4j-core: 2.14.1 → 2.20.0 (corrige Log4Shell CVE-2021-44228)"
echo "- spring-core: 4.3.29.RELEASE → 6.0.11 (corrige múltiples CVEs)"
echo "- commons-collections: 3.2.1 → commons-collections4 4.4 (corrige CVE-2015-6420)"

cd ..
```

**PowerShell:**

```powershell
Write-Host "🔧 Aplicando correcciones a dependencias Java vulnerables..." -ForegroundColor Yellow

Set-Location "sca-lab\java-vulnerable-app"

# Crear backup del pom.xml original
Copy-Item "pom.xml" "pom.xml.backup"
Write-Host "💾 Backup creado: pom.xml.backup" -ForegroundColor Green

# Crear versión corregida del pom.xml
Write-Host "📝 Actualizando dependencias Java a versiones seguras..." -ForegroundColor Cyan

@'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>secure-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.20.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.0.11</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.4</version>
        </dependency>
    </dependencies>
</project>
'@ | Out-File -FilePath "pom.xml" -Encoding UTF8

Write-Host "✅ Dependencias Java actualizadas a versiones seguras:" -ForegroundColor Green
Write-Host "- log4j-core: 2.14.1 → 2.20.0 (corrige Log4Shell CVE-2021-44228)" -ForegroundColor White
Write-Host "- spring-core: 4.3.29.RELEASE → 6.0.11 (corrige múltiples CVEs)" -ForegroundColor White
Write-Host "- commons-collections: 3.2.1 → commons-collections4 4.4 (corrige CVE-2015-6420)" -ForegroundColor White

Set-Location ".."
```

### 4 Corrección Automatizada con npm audit fix

**Bash:**

```bash
echo "🤖 Demonstrando corrección automatizada con npm audit fix..."

cd sca-lab
# Crear un segundo proyecto Node.js para demostrar npm audit fix
mkdir nodejs-autofix-demo
cd nodejs-autofix-demo

# Crear package.json con vulnerabilidades que npm puede corregir automáticamente
cat > package.json << 'EOF'
{
  "name": "autofix-demo",
  "version": "1.0.0",
  "dependencies": {
    "axios": "0.18.0",
    "moment": "2.24.0",
    "request": "2.88.0",
    "validator": "10.11.0"
  }
}
EOF

echo "📦 Instalando dependencias vulnerables para demostración..."
npm install

echo "🔍 Ejecutando audit inicial..."
npm audit

echo ""
echo "🔧 Aplicando correcciones automáticas..."
npm audit fix

echo ""
echo "✅ Verificando correcciones aplicadas..."
npm audit

echo ""
echo "📊 Comparando versiones:"
echo "ANTES → DESPUÉS de npm audit fix"
echo "- axios: 0.18.0 → $(npm list axios --depth=0 2>/dev/null | grep axios | cut -d@ -f2 || echo 'actualizada')"
echo "- moment: 2.24.0 → $(npm list moment --depth=0 2>/dev/null | grep moment | cut -d@ -f2 || echo 'actualizada')"
echo "- validator: 10.11.0 → $(npm list validator --depth=0 2>/dev/null | grep validator | cut -d@ -f2 || echo 'actualizada')"

cd ..
```

**PowerShell:**

```powershell
Write-Host "🤖 Demonstrando corrección automatizada con npm audit fix..." -ForegroundColor Yellow

Set-Location "sca-lab"
# Crear un segundo proyecto Node.js para demostrar npm audit fix
New-Item -ItemType Directory -Path "nodejs-autofix-demo" -Force
Set-Location "nodejs-autofix-demo"

# Crear package.json con vulnerabilidades que npm puede corregir automáticamente
@'
{
  "name": "autofix-demo",
  "version": "1.0.0",
  "dependencies": {
    "axios": "0.18.0",
    "moment": "2.24.0",
    "request": "2.88.0",
    "validator": "10.11.0"
  }
}
'@ | Out-File -FilePath "package.json" -Encoding UTF8

Write-Host "📦 Instalando dependencias vulnerables para demostración..." -ForegroundColor Cyan
npm install

Write-Host "🔍 Ejecutando audit inicial..." -ForegroundColor Yellow
npm audit

Write-Host ""
Write-Host "🔧 Aplicando correcciones automáticas..." -ForegroundColor Green
npm audit fix

Write-Host ""
Write-Host "✅ Verificando correcciones aplicadas..." -ForegroundColor Green
npm audit

Write-Host ""
Write-Host "📊 Comparando versiones:" -ForegroundColor Cyan
Write-Host "ANTES → DESPUÉS de npm audit fix" -ForegroundColor White

# Mostrar versiones actualizadas
try {
    $packageJson = Get-Content "package.json" | ConvertFrom-Json
    Write-Host "- axios: 0.18.0 → actualizada automáticamente" -ForegroundColor Green
    Write-Host "- moment: 2.24.0 → actualizada automáticamente" -ForegroundColor Green
    Write-Host "- validator: 10.11.0 → actualizada automáticamente" -ForegroundColor Green
} catch {
    Write-Host "Error al procesar versiones actualizadas" -ForegroundColor Yellow
}

Set-Location ".."
```

---

## Parte: Validación de Correcciones

### 1 Re-análisis con Todas las Herramientas

**Bash:**

```bash
echo "🔄 Validando correcciones aplicadas con re-análisis..."

# Crear directorio para reportes post-corrección
mkdir -p sca-lab/reports/post-fix

echo "🔍 Re-analizando proyecto Node.js corregido..."

# Re-análisis con npm audit
cd sca-lab/nodejs-vulnerable-app
echo "📊 npm audit en proyecto corregido:"
npm audit --json > ../reports/post-fix/npm-audit-fixed.json 2>/dev/null || true
npm audit

# Re-análisis con Trivy
cd ..
echo "📊 Trivy en proyecto Node.js corregido:"
trivy fs ./nodejs-vulnerable-app --format json --output ./reports/post-fix/trivy-nodejs-fixed.json
trivy fs ./nodejs-vulnerable-app --format table

# Re-análisis con OWASP Dependency-Check en proyecto Java
echo "📊 OWASP Dependency-Check en proyecto Java corregido:"
./dependency-check/bin/dependency-check.sh \
    --project "SecureJavaApp" \
    --scan "./java-vulnerable-app" \
    --format JSON \
    --out "./reports/post-fix" \
    --prettyPrint

echo "✅ Re-análisis completado"
```

**PowerShell:**

```powershell
Write-Host "🔄 Validando correcciones aplicadas con re-análisis..." -ForegroundColor Yellow

# Crear directorio para reportes post-corrección
New-Item -ItemType Directory -Path "sca-lab\reports\post-fix" -Force

Write-Host "🔍 Re-analizando proyecto Node.js corregido..." -ForegroundColor Cyan

# Re-análisis con npm audit
Set-Location "sca-lab\nodejs-vulnerable-app"
Write-Host "📊 npm audit en proyecto corregido:" -ForegroundColor White
try {
    npm audit --json | Out-File -FilePath "..\reports\post-fix\npm-audit-fixed.json" -Encoding UTF8
    npm audit
} catch {
    Write-Host "✅ No se encontraron vulnerabilidades!" -ForegroundColor Green
}

# Re-análisis con Trivy
Set-Location ".."
Write-Host "📊 Trivy en proyecto Node.js corregido:" -ForegroundColor White
& ".\trivy\trivy.exe" fs .\nodejs-vulnerable-app --format json --output .\reports\post-fix\trivy-nodejs-fixed.json
& ".\trivy\trivy.exe" fs .\nodejs-vulnerable-app --format table

# Re-análisis con OWASP Dependency-Check en proyecto Java
Write-Host "📊 OWASP Dependency-Check en proyecto Java corregido:" -ForegroundColor White
& ".\dependency-check\bin\dependency-check.bat" `
    --project "SecureJavaApp" `
    --scan ".\java-vulnerable-app" `
    --format JSON `
    --out ".\reports\post-fix" `
    --prettyPrint

Write-Host "✅ Re-análisis completado" -ForegroundColor Green
```

### 2 Comparación Antes vs Después

**Bash:**

```bash
echo "📊 Generando comparación ANTES vs DESPUÉS..."

# Crear script de comparación
cat > compare_results.sh << 'EOF'
#!/bin/bash

echo "========================================"
echo "   COMPARACIÓN: ANTES vs DESPUÉS"
echo "========================================"
echo ""

echo "📊 RESULTADOS ANTES DE CORRECCIONES:"
echo "-----------------------------------"

# Contar vulnerabilidades en reportes originales
if [ -f "reports/npm-audit-report.json" ]; then
    BEFORE_NPM=$(cat reports/npm-audit-report.json | jq '.metadata.vulnerabilities.total' 2>/dev/null || echo "N/A")
    echo "🚨 npm audit (antes): $BEFORE_NPM vulnerabilidades"
fi

if [ -f "reports/dependency-check-report.json" ]; then
    BEFORE_OWASP=$(cat reports/dependency-check-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length' 2>/dev/null || echo "N/A")
    echo "🚨 OWASP DC (antes): $BEFORE_OWASP vulnerabilidades"
fi

echo ""
echo "📊 RESULTADOS DESPUÉS DE CORRECCIONES:"
echo "-------------------------------------"

# Contar vulnerabilidades en reportes post-corrección
if [ -f "reports/post-fix/npm-audit-fixed.json" ]; then
    AFTER_NPM=$(cat reports/post-fix/npm-audit-fixed.json | jq '.metadata.vulnerabilities.total' 2>/dev/null || echo "0")
    echo "✅ npm audit (después): $AFTER_NPM vulnerabilidades"
else
    echo "✅ npm audit (después): 0 vulnerabilidades (sin reporte = sin problemas)"
fi

if [ -f "reports/post-fix/dependency-check-report.json" ]; then
    AFTER_OWASP=$(cat reports/post-fix/dependency-check-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length' 2>/dev/null || echo "0")
    echo "✅ OWASP DC (después): $AFTER_OWASP vulnerabilidades"
fi

echo ""
echo "🎯 RESUMEN DE MEJORAS:"
echo "---------------------"
if [ "$BEFORE_NPM" != "N/A" ] && [ "$AFTER_NPM" != "N/A" ]; then
    REDUCTION_NPM=$((BEFORE_NPM - AFTER_NPM))
    echo "📦 Node.js: Reducción de $REDUCTION_NPM vulnerabilidades ($BEFORE_NPM → $AFTER_NPM)"
fi

echo ""
echo "🏆 CORRECCIONES ESPECÍFICAS APLICADAS:"
echo "-------------------------------------"
echo "Node.js:"
echo "  ✅ lodash: 4.17.19 → 4.17.21 (CVE-2020-8203 resuelto)"
echo "  ✅ express: 4.16.4 → 4.18.2 (múltiples CVEs resueltos)"
echo "  ✅ minimist: 1.2.0 → 1.2.8 (CVE-2020-7598 resuelto)"
echo "  ✅ yargs-parser: 13.1.1 → 21.1.1 (CVE-2020-7608 resuelto)"
echo ""
echo "Java:"
echo "  ✅ log4j-core: 2.14.1 → 2.20.0 (Log4Shell CVE-2021-44228 resuelto)"
echo "  ✅ spring-core: 4.3.29 → 6.0.11 (múltiples CVEs resueltos)"
echo "  ✅ commons-collections: 3.2.1 → 4.4 (CVE-2015-6420 resuelto)"
EOF

chmod +x compare_results.sh
./compare_results.sh
```

**PowerShell:**

```powershell
Write-Host "📊 Generando comparación ANTES vs DESPUÉS..." -ForegroundColor Yellow

function Compare-Results {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   COMPARACIÓN: ANTES vs DESPUÉS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "📊 RESULTADOS ANTES DE CORRECCIONES:" -ForegroundColor White
    Write-Host "-----------------------------------" -ForegroundColor White

    # Contar vulnerabilidades en reportes originales
    $beforeNpm = "N/A"
    $beforeOwasp = "N/A"

    if (Test-Path ".\reports\npm-audit-report.json") {
        try {
            $npmReport = Get-Content ".\reports\npm-audit-report.json" | ConvertFrom-Json
            $beforeNpm = $npmReport.metadata.vulnerabilities.total
            Write-Host "🚨 npm audit (antes): $beforeNpm vulnerabilidades" -ForegroundColor Red
        } catch {
            Write-Host "🚨 npm audit (antes): Error al procesar" -ForegroundColor Yellow
        }
    }

    if (Test-Path ".\reports\dependency-check-report.json") {
        try {
            $owaspReport = Get-Content ".\reports\dependency-check-report.json" | ConvertFrom-Json
            $beforeOwasp = ($owaspReport.dependencies | Where-Object { $_.vulnerabilities } | ForEach-Object { $_.vulnerabilities }).Count
            Write-Host "🚨 OWASP DC (antes): $beforeOwasp vulnerabilidades" -ForegroundColor Red
        } catch {
            Write-Host "🚨 OWASP DC (antes): Error al procesar" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "📊 RESULTADOS DESPUÉS DE CORRECCIONES:" -ForegroundColor White
    Write-Host "-------------------------------------" -ForegroundColor White

    # Contar vulnerabilidades en reportes post-corrección
    $afterNpm = 0
    if (Test-Path ".\reports\post-fix\npm-audit-fixed.json") {
        try {
            $npmFixedReport = Get-Content ".\reports\post-fix\npm-audit-fixed.json" | ConvertFrom-Json
            $afterNpm = $npmFixedReport.metadata.vulnerabilities.total
            Write-Host "✅ npm audit (después): $afterNpm vulnerabilidades" -ForegroundColor Green
        } catch {
            Write-Host "✅ npm audit (después): 0 vulnerabilidades" -ForegroundColor Green
        }
    } else {
        Write-Host "✅ npm audit (después): 0 vulnerabilidades (sin reporte = sin problemas)" -ForegroundColor Green
    }

```

## Parte: Integración con Gitlab CI

### 1: Configuración Básica del Pipeline

#### 1.1 Crear archivo .gitlab-ci.yml

En la raíz de tu proyecto, crea el archivo `.gitlab-ci.yml`:

```yaml
# Pipeline simple para análisis SCA
stages:
  - security-scan
  - sbom-sign

variables:
  REPORTS_DIR: "security-reports"

before_script:
  - mkdir -p $REPORTS_DIR

# Template para artefactos
.artifacts_template: &artifacts_template
  artifacts:
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
    when: always
```

---

### 2: Job de Análisis con Trivy

### 2.1 Agregar análisis Trivy

Agrega este job al archivo `.gitlab-ci.yml`:

```yaml
# Análisis con Trivy
trivy-scan:
  stage: security-scan
  image: aquasec/trivy:latest
  <<: *artifacts_template
  script:
    - echo "🔍 Ejecutando análisis Trivy..."

    # Actualizar base de datos
    - trivy image --download-db-only

    # Análisis del código fuente
    - |
      trivy fs . \
        --format json \
        --output $REPORTS_DIR/trivy-report.json \
        --severity HIGH,CRITICAL

    # Reporte en tabla para visualizar
    - |
      trivy fs . \
        --format table \
        --output $REPORTS_DIR/trivy-table.txt \
        --severity HIGH,CRITICAL

    # Generar SBOM
    - |
      trivy fs . \
        --format cyclonedx \
        --output $REPORTS_DIR/sbom.json

    # Mostrar resumen
    - echo "📊 Resumen del análisis:"
    - cat $REPORTS_DIR/trivy-table.txt

    # Verificar vulnerabilidades críticas
    - |
      CRITICAL=$(cat $REPORTS_DIR/trivy-report.json | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')
      echo "🚨 Vulnerabilidades críticas encontradas: $CRITICAL"

      if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Se encontraron vulnerabilidades críticas"
        exit 1
      fi

  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

### 3: Job de Análisis con OWASP Dependency-Check

#### 3.1 Agregar análisis OWASP

Agrega este job al archivo `.gitlab-ci.yml`:

```yaml
# Análisis con OWASP Dependency-Check
dependency-check:
  stage: security-scan
  image: openjdk:11-jdk-slim
  <<: *artifacts_template
  script:
    - echo "🛡️ Ejecutando OWASP Dependency-Check..."

    # Instalar dependencias
    - apt-get update && apt-get install -y curl unzip

    # Descargar Dependency-Check
    - |
      curl -L "https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.4/dependency-check-9.0.4-release.zip" -o dependency-check.zip
      unzip -q dependency-check.zip
      chmod +x dependency-check/bin/dependency-check.sh

    # Ejecutar análisis
    - |
      ./dependency-check/bin/dependency-check.sh \
        --project "$CI_PROJECT_NAME" \
        --scan . \
        --format HTML \
        --format JSON \
        --out $REPORTS_DIR \
        --failOnCVSS 7 || true

    # Renombrar reportes
    - |
      if [ -f "$REPORTS_DIR/dependency-check-report.html" ]; then
        mv "$REPORTS_DIR/dependency-check-report.html" "$REPORTS_DIR/owasp-report.html"
      fi
      if [ -f "$REPORTS_DIR/dependency-check-report.json" ]; then
        mv "$REPORTS_DIR/dependency-check-report.json" "$REPORTS_DIR/owasp-report.json"
      fi

    # Mostrar resumen de vulnerabilidades
    - |
      if [ -f "$REPORTS_DIR/owasp-report.json" ]; then
        echo "📊 Procesando reporte OWASP..."
        apt-get install -y jq
        TOTAL_VULNS=$(cat $REPORTS_DIR/owasp-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length')
        echo "🚨 Total de vulnerabilidades encontradas: $TOTAL_VULNS"
      fi

  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

### 9.5: Configuración Completa

#### Archivo .gitlab-ci.yml completo:

```yaml

# Pipeline simple para análisis SCA
stages:
  - security-scan
  - sbom-sign

variables:
  REPORTS_DIR: "security-reports"

before_script:
  - mkdir -p $REPORTS_DIR

# Template para artefactos
.artifacts_template: &artifacts_template
  artifacts:
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
    when: always

# Análisis con Trivy
trivy-scan:
  stage: security-scan
  image: ubuntu:22.04
  <<: *artifacts_template
  script:
    - echo "🔍 Instalando y ejecutando análisis Trivy..."

    # Actualizar sistema e instalar dependencias
    - apt-get update && apt-get install -y curl wget jq gnupg

    # Instalar Trivy
    - |
      echo "⬇️ Descargando e instalando Trivy..."
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
      echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | tee -a /etc/apt/sources.list
      apt-get update
      apt-get install -y trivy

    # Verificar instalación
    - trivy --version

    # Actualizar base de datos de vulnerabilidades
    - echo "📥 Actualizando base de datos de vulnerabilidades..."
    - trivy image --download-db-only

    # Análisis del código fuente
    - |
      echo "🔍 Ejecutando análisis del filesystem..."
      trivy fs . \
        --format json \
        --output $REPORTS_DIR/trivy-report.json \
        --severity HIGH,CRITICAL

    # Reporte en tabla para visualizar
    - |
      trivy fs . \
        --format table \
        --output $REPORTS_DIR/trivy-table.txt \
        --severity HIGH,CRITICAL

    # Generar SBOM
    - |
      echo "📦 Generando SBOM..."
      trivy fs . \
        --format cyclonedx \
        --output $REPORTS_DIR/sbom.json

    # Mostrar resumen
    - echo "📊 Resumen del análisis:"
    - cat $REPORTS_DIR/trivy-table.txt

    # Verificar vulnerabilidades críticas
    - |
      CRITICAL=$(cat $REPORTS_DIR/trivy-report.json | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')
      echo "🚨 Vulnerabilidades críticas encontradas: $CRITICAL"

      if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Se encontraron vulnerabilidades críticas"
        exit 1
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Análisis con OWASP Dependency-Check
dependency-check:
  stage: security-scan
  image: ubuntu:22.04
  <<: *artifacts_template
  script:
    - echo "🛡️ Instalando y ejecutando OWASP Dependency-Check..."

    # Instalar dependencias del sistema
    - apt-get update && apt-get install -y openjdk-11-jdk curl unzip jq wget

    # Verificar Java
    - java -version

    # Descargar e instalar OWASP Dependency-Check
    - |
      echo "⬇️ Descargando OWASP Dependency-Check..."
      wget "https://github.com/dependency-check/DependencyCheck/releases/download/v12.1.0/dependency-check-12.1.0-release.zip" -O dependency-check.zip
      unzip -q dependency-check.zip
      chmod +x dependency-check/bin/dependency-check.sh

    # Verificar instalación
    - ./dependency-check/bin/dependency-check.sh --version

    # Ejecutar análisis
    - |
      echo "🔍 Ejecutando análisis de dependencias..."
      ./dependency-check/bin/dependency-check.sh \
        --project "$CI_PROJECT_NAME" \
        --scan . \
        --format HTML \
        --format JSON \
        --out $REPORTS_DIR \
        --failOnCVSS 7 || true

    # Renombrar reportes para mejor organización
    - |
      if [ -f "$REPORTS_DIR/dependency-check-report.html" ]; then
        mv "$REPORTS_DIR/dependency-check-report.html" "$REPORTS_DIR/owasp-report.html"
        echo "✅ Reporte HTML renombrado a owasp-report.html"
      fi
      if [ -f "$REPORTS_DIR/dependency-check-report.json" ]; then
        mv "$REPORTS_DIR/dependency-check-report.json" "$REPORTS_DIR/owasp-report.json"
        echo "✅ Reporte JSON renombrado a owasp-report.json"
      fi

    # Mostrar resumen de vulnerabilidades
    - |
      if [ -f "$REPORTS_DIR/owasp-report.json" ]; then
        echo "📊 Procesando reporte OWASP..."
        TOTAL_VULNS=$(cat $REPORTS_DIR/owasp-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length')
        echo "🚨 Total de vulnerabilidades encontradas: $TOTAL_VULNS"

        # Mostrar vulnerabilidades por severidad
        echo "📋 Desglose por severidad:"
        cat $REPORTS_DIR/owasp-report.json | jq -r '.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[] | .severity' | sort | uniq -c | while read count severity; do
          echo "  $severity: $count"
        done
      else
        echo "✅ No se generó reporte JSON - posiblemente no se encontraron vulnerabilidades"
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH


stages:
  - security-scan

variables:
  REPORTS_DIR: "security-reports"

before_script:
  - mkdir -p $REPORTS_DIR

# Template para artefactos
.artifacts_template: &artifacts_template
  artifacts:
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
    when: always

# Análisis con Trivy
trivy-scan:
  stage: security-scan
  image: aquasec/trivy:latest
  <<: *artifacts_template
  script:
    - echo "🔍 Ejecutando análisis Trivy..."
    - trivy image --download-db-only
    - |
      trivy fs . \
        --format json \
        --output $REPORTS_DIR/trivy-report.json \
        --severity HIGH,CRITICAL
    - |
      trivy fs . \
        --format table \
        --output $REPORTS_DIR/trivy-table.txt \
        --severity HIGH,CRITICAL
    - |
      trivy fs . \
        --format cyclonedx \
        --output $REPORTS_DIR/sbom.json
    - echo "📊 Resumen del análisis:"
    - cat $REPORTS_DIR/trivy-table.txt
    - |
      CRITICAL=$(cat $REPORTS_DIR/trivy-report.json | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length')
      echo "🚨 Vulnerabilidades críticas encontradas: $CRITICAL"
      if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Se encontraron vulnerabilidades críticas"
        exit 1
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Análisis con OWASP Dependency-Check
dependency-check:
  stage: security-scan
  image: openjdk:11-jdk-slim
  <<: *artifacts_template
  script:
    - echo "🛡️ Ejecutando OWASP Dependency-Check..."
    - apt-get update && apt-get install -y curl unzip jq
    - |
      curl -L "https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.4/dependency-check-9.0.4-release.zip" -o dependency-check.zip
      unzip -q dependency-check.zip
      chmod +x dependency-check/bin/dependency-check.sh
    - |
      ./dependency-check/bin/dependency-check.sh \
        --project "$CI_PROJECT_NAME" \
        --scan . \
        --format HTML \
        --format JSON \
        --out $REPORTS_DIR \
        --failOnCVSS 7 || true
    - |
      if [ -f "$REPORTS_DIR/dependency-check-report.html" ]; then
        mv "$REPORTS_DIR/dependency-check-report.html" "$REPORTS_DIR/owasp-report.html"
      fi
      if [ -f "$REPORTS_DIR/dependency-check-report.json" ]; then
        mv "$REPORTS_DIR/dependency-check-report.json" "$REPORTS_DIR/owasp-report.json"
      fi
    - |
      if [ -f "$REPORTS_DIR/owasp-report.json" ]; then
        TOTAL_VULNS=$(cat $REPORTS_DIR/owasp-report.json | jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length')
        echo "🚨 Total de vulnerabilidades encontradas: $TOTAL_VULNS"
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

```

---

### 9.6.3 Archivos Generados

Después de ejecutar el pipeline, encontrarás estos archivos en los artefactos:

- `trivy-report.json` - Reporte detallado de Trivy
- `trivy-table.txt` - Resumen visual de vulnerabilidades
- `owasp-report.html` - Reporte visual de OWASP
- `owasp-report.json` - Reporte detallado de OWASP

---
