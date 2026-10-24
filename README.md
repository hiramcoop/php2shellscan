# php2shell-version-scanner

Escáner **defensivo por versión** para detectar servidores PHP afectados por
**PHP2Shell** — las vulnerabilidades críticas del núcleo de PHP
**CVE-2026-109618** y **CVE-2026-109619** (CVSS 9.2).

El script consulta la versión de PHP que un servidor expone en sus cabeceras
HTTP (`X-Powered-By` / `Server`) y la compara contra las versiones corregidas
oficiales. **Solo detecta: no lanza exploits ni envía payloads.** Es no
destructivo.

> ⚠️ **Uso autorizado únicamente.** Ejecútalo sobre servidores que administras o
> para los que tienes permiso explícito. No lo uses contra infraestructura de
> terceros.

---

## Contexto de la vulnerabilidad

| | |
|---|---|
| **CVE-2026-109618** | Corrupción de memoria (OOM) → ejecución de código sin autenticación |
| **CVE-2026-109619** | Estado global obsoleto entre peticiones → use-after-free |
| **Severidad** | Crítica (CVSS 9.2) |
| **Alcance** | Núcleo de PHP: afecta a casi todas las versiones desde PHP 5.4 (más de una década) |

Como el fallo está en **PHP mismo**, afecta a cualquier aplicación que corra
sobre una versión vulnerable (WordPress, Drupal, Joomla, Magento, Laravel,
cPanel, Plesk, desarrollos a medida, etc.). Actualizar solo la aplicación **no**
cierra la brecha: hay que actualizar PHP.

### Versiones corregidas

| Rama PHP | Versión afectada | Primera versión corregida |
|---|---|---|
| 8.2 | < 8.2.35 | **8.2.35** |
| 8.3 | < 8.3.36 | **8.3.36** |
| 8.4 | < 8.4.27 | **8.4.27** |
| 8.5 | < 8.5.12 | **8.5.12** |

Las ramas 8.1 y anteriores están sin soporte oficial; el equipo de seguridad de
PHP publicó *backports* de código fuente para 7.4, 8.0 y 8.1. Lo recomendable es
migrar a una rama con mantenimiento (8.2+).

---

## Requisitos

- Python 3.8 o superior
- Sin dependencias externas (solo librería estándar)

---

## Uso

```bash
# Una URL o IP:
python3 php_version_scan.py https://tienda.midominio.com
python3 php_version_scan.py 192.168.1.10

# Varias de golpe (mezcla IPs y URLs):
python3 php_version_scan.py 192.168.1.10 10.0.0.5 https://web.midominio.com

# Leer los objetivos desde un archivo (uno por línea; admite CSV):
python3 php_version_scan.py --input URLs.csv

# Leer del archivo y guardar el informe de salida:
python3 php_version_scan.py --input URLs.csv --csv informe.csv
```

### Opciones

| Opción | Descripción |
|---|---|
| `-i`, `--input RUTA` | Archivo **de entrada** con hosts/URLs (uno por línea; si es CSV usa la 1ª columna, ignora encabezado y comentarios `#`) |
| `--csv RUTA` | Archivo **de salida**: guarda el informe en CSV |
| `--timeout N` | Segundos de espera por petición (por defecto 10) |
| `--workers N` | Peticiones concurrentes (por defecto 10) |
| `--no-color` | Salida sin colores |

> `--input` es la lista que vas a escanear; `--csv` es el informe que genera. Son archivos distintos.

### Ejemplo de salida

```
# PHP2Shell — CVE-2026-109618, CVE-2026-109619
# Objetivos: 1 | Umbrales: {'8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12'}

[AFECTADO] https://tienda.midominio.com
      - X-Powered-By: PHP/8.3.6                 8.3.6      8.3.6 < 8.3.36

# Resumen
  AFECTADO: 1
  NO AFECTADO: 0
  DESCONOCIDO: 0
```

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Ningún servidor afectado |
| `1` | Hubo resultados DESCONOCIDO (sin afectados confirmados) |
| `2` | Al menos un servidor **AFECTADO** |

Útil para integrarlo en CI o en un cron.

---

## ⚠️ Limitaciones importantes

Este método se basa en el **número de versión** que anuncia el servidor, y eso
tiene dos limitaciones que debes conocer:

1. **Servidores que ocultan la versión.** Muchos deshabilitan `expose_php`, así
   que no publican la versión en las cabeceras. En esos casos el resultado será
   `DESCONOCIDO` — **no significa que estén a salvo**, solo que no se puede
   determinar por HTTP.

2. **Parches *backported* de distribuciones (falsos positivos).** Debian,
   Ubuntu, RHEL, AlmaLinux y otras aplican el parche **sin cambiar el número de
   versión visible**. Un servidor puede mostrar `PHP 8.3.6` y estar **ya
   parcheado**. Para confirmarlo, revisa el changelog del paquete y busca el CVE:

   ```bash
   # Debian / Ubuntu
   apt changelog php | grep -i 2026-109618

   # RHEL / AlmaLinux / Rocky
   rpm -q --changelog php | grep -i 2026-109618
   ```

Para una confirmación definitiva, valida la versión instalada directamente en el
servidor, no solo por HTTP.

---

## Configuración

Los umbrales de versión están en el diccionario `FIXED_VERSIONS`, al inicio del
script. Si un aviso oficial de PHP publica otras versiones de corrección, edítalo
ahí.

---

## Referencias

- [PHP — ChangeLog oficial](https://www.php.net/ChangeLog-8.php)
- [JFrog Security Research — PHP2Shell](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- [The Hacker News — Emergency patches](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)

---

## Licencia

MIT. Úsalo, modifícalo y compártelo libremente. Sin garantía.
