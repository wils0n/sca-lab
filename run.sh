echo "📊 Generando resumen comparativo de herramientas SCA..."
cd sca-lab
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
