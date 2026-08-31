"""El README es texto publicado: estas pruebas lo vigilan.

Una credencial que el emisor no respalda es una afirmacion falsa aunque
compile todo lo demas. La ISC2 CC ya reaparecio en cinco sitios distintos
(la web, el README de la organizacion, el README personal, los topics de
GitHub y este mismo repositorio) porque nada automatico la buscaba.
"""

from __future__ import annotations

import pathlib
import re

RAIZ = pathlib.Path(__file__).resolve().parent.parent

# Credenciales que NO pueden publicarse: no hay certificado que las acredite
# y, en el caso de la ISC2 CC, el emisor dio por terminado el estatus en
# noviembre de 2025.
PROHIBIDAS = [
    re.compile(r"ISC.?2", re.IGNORECASE),
    re.compile(r"Certified in Cybersecurity", re.IGNORECASE),
    re.compile(r"Palo Alto Networks Cybersecurity", re.IGNORECASE),
    re.compile(r"IBM Data (Analyst|Science)", re.IGNORECASE),
    re.compile(r"Google Data Analytics", re.IGNORECASE),
]

DOCUMENTOS = sorted(
    p
    for p in RAIZ.rglob("*.md")
    if ".git" not in p.parts and "node_modules" not in p.parts
)


def test_hay_documentos_que_revisar():
    """Sin esto, un glob roto dejaria el test pasando en vacio."""
    assert DOCUMENTOS, "no se encontro ningun .md: el test estaria pasando por vacio"


def test_ninguna_credencial_sin_respaldo_en_los_documentos():
    encontrados = [
        f"{p.relative_to(RAIZ)}: {patron.pattern}"
        for p in DOCUMENTOS
        for patron in PROHIBIDAS
        if patron.search(p.read_text(encoding="utf-8"))
    ]
    assert not encontrados, (
        "Credencial sin respaldo en texto publicado:\n  " + "\n  ".join(encontrados)
    )
