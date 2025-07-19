# Laboratorio de Análisis de Dependencias - SCA (Software Composition Analysis)

**Nivel**: Intermedio/Avanzado  
**Objetivo**: Implementar herramientas SCA para detectar y gestionar vulnerabilidades en dependencias de software

## 📋 Descripción

Este laboratorio proporciona una experiencia práctica completa en el análisis de composición de software (SCA), enfocándose en la detección, análisis y corrección de vulnerabilidades en dependencias de aplicaciones Java y Node.js.

## 🔧 Requisitos Previos

### Herramientas Base

- **Git**: Control de versiones
- **Java 11+**: Para la aplicación Java
- **Node.js 16+**: Para la aplicación Node.js
- **Maven**: Gestión de dependencias Java
- **Docker** (opcional): Para herramientas containerizadas

### Herramientas SCA que se Instalan Durante el Lab

- **Trivy**: Escáner de vulnerabilidades
- **Snyk CLI**: Análisis de seguridad
- **npm audit**: Herramienta nativa de Node.js
- **OWASP Dependency-Check**: Análisis de dependencias

## 📊 Herramientas y Análisis Incluidos

### 🔍 Herramientas de Análisis

1. **Trivy**

   - Escáner de vulnerabilidades multiplataforma
   - Genera reportes JSON y HTML
   - Crea SBOM en formatos CycloneDX y SPDX

2. **Snyk**

   - Plataforma de seguridad para desarrolladores
   - Análisis de dependencias Java y Node.js
   - Base de datos de vulnerabilidades actualizada

3. **npm audit**

   - Herramienta nativa de Node.js
   - Análisis rápido de vulnerabilidades
   - Correcciones automáticas disponibles

4. **OWASP Dependency-Check**
   - Herramienta de código abierto
   - Identifica componentes con vulnerabilidades conocidas
   - Reportes detallados en múltiples formatos

### 📦 Aplicaciones de Prueba

#### Java Vulnerable App

- **Framework**: Maven
- **Dependencias Vulnerables**:
  - `log4j-core:2.15.0` (Log4Shell CVE-2021-44228)
  - Spring Framework versiones antiguas
  - Commons Collections vulnerables

#### Node.js Vulnerable App

- **Framework**: Express.js
- **Dependencias Vulnerables**:
  - `lodash:4.17.19` (CVE-2020-8203)
  - `express:4.16.4` (CVE-2022-24999)
  - `minimist:1.2.0` (CVE-2020-7598)
  - `yargs-parser:13.1.1` (CVE-2020-7608)

## 📈 Flujo del Laboratorio

### Fase 1: Configuración (15 min)

- Preparación del entorno
- Instalación de dependencias
- Verificación de herramientas

### Fase 2: Análisis con Trivy (20 min)

- Instalación de Trivy
- Escaneo de vulnerabilidades
- Generación de SBOM

### Fase 3: Análisis con Snyk (15 min)

- Configuración de Snyk CLI
- Análisis de proyectos Java y Node.js
- Comparación de resultados

### Fase 4: Análisis Comparativo (10 min)

- Comparación de herramientas
- Generación de reportes consolidados
- Identificación de fortalezas de cada herramienta

### Fase 5: Corrección de Vulnerabilidades (25 min)

- Análisis detallado de vulnerabilidades
- Corrección manual de dependencias
- Corrección automatizada con `npm audit fix`

### Fase 6: Validación (15 min)

- Re-análisis post-corrección
- Comparación antes vs después
- Verificación de mejoras

### Fase 7: Integración CI/CD (20 min)

- Configuración de GitLab CI
- Pipeline de seguridad automatizado
- Políticas de fallo por vulnerabilidades críticas

## 📋 Resultados del Laboratorio

### Reportes Generados

- **JSON**: Reportes estructurados para procesamiento automatizado
- **HTML**: Reportes visuales para revisión manual
- **SBOM**: Software Bills of Materials en formatos estándar

### Archivos de Salida

```
reports/
├── npm-audit-report.json         # npm audit results
├── snyk-java-report.json         # Snyk Java analysis
├── snyk-nodejs-report.json       # Snyk Node.js analysis
├── trivy-java-report.json        # Trivy Java scan
├── trivy-nodejs-report.json      # Trivy Node.js scan
└── post-fix/                     # Post-remediation reports

sbom/
├── java-sbom.json               # Java SBOM (CycloneDX)
├── java-sbom-spdx.json          # Java SBOM (SPDX)
└── nodejs-sbom.json             # Node.js SBOM (CycloneDX)
```

## 🏆 Objetivos de Aprendizaje

Al completar este laboratorio, habrás aprendido a:

1. **Configurar herramientas SCA** en diferentes entornos
2. **Identificar vulnerabilidades** en dependencias de software
3. **Comparar herramientas** y entender sus fortalezas
4. **Generar SBOM** en formatos estándar de la industria
5. **Corregir vulnerabilidades** manual y automáticamente
6. **Validar correcciones** con re-análisis
7. **Integrar SCA en pipelines CI/CD**
8. **Implementar políticas de seguridad** automatizadas

## 📚 Recursos Adicionales

- **Guía Completa**: `sca-guide.md` - Tutorial paso a paso detallado
- **OWASP Dependency-Check**: [Documentación oficial](https://owasp.org/www-project-dependency-check/)
- **Trivy**: [Documentación oficial](https://trivy.dev/)
- **Snyk**: [Documentación oficial](https://docs.snyk.io/)

## 🤝 Contribuciones

Este laboratorio está diseñado para fines educativos. Las aplicaciones vulnerables **NO** deben usarse en producción.

## ⚠️ Advertencias de Seguridad

- Las dependencias incluidas son **intencionalmente vulnerables**
- **NO** usar estas configuraciones en entornos de producción
- Las claves y secretos son solo para demostración
- Siempre mantener las herramientas SCA actualizadas

## 📄 Licencia

Este proyecto tiene fines educativos y de demostración.

---

**🎯 ¡Inicia tu journey en SCA y fortalece la seguridad de tus aplicaciones!**
