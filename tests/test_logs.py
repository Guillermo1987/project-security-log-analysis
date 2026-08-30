"""Pruebas del analisis de logs.

Lo que se fija aqui es que las cifras del informe salen de contar el fichero
UNA vez y no de volver a parsear el Markdown, y que una linea que el parser no
entiende se cuenta como hallazgo en lugar de desaparecer en silencio. Eso
ultimo es la diferencia entre «no hay amenazas» y «no supe leer la mitad del
registro».
"""

import json

import pytest

from log_analysis import (
    LOG_PATTERN,
    THREAT_EVENTS,
    analyze,
    analyze_logs,
    build_report,
    export_json,
)
from generate_logs import generate_entries

LINEAS = [
    "2026-03-15 08:15:00 192.168.1.10 [LOGIN_SUCCESS] User admin logged in",
    "2026-03-15 08:16:00 10.0.0.5 [LOGIN_FAILED] Bad password for root",
    "2026-03-15 08:17:00 10.0.0.5 [LOGIN_FAILED] Bad password for root",
    "2026-03-15 23:40:00 10.0.0.5 [BRUTE_FORCE_ATTEMPT] 40 attempts in 60s",
    "2026-03-16 02:00:00 203.0.113.9 [PORT_SCAN_DETECTED] Sequential probe",
    "2026-03-16 09:00:00 192.168.1.10 [ACCESS_DENIED] /admin denied",
]


@pytest.fixture
def registro(tmp_path):
    f = tmp_path / "security_logs.txt"
    f.write_text("\n".join(LINEAS) + "\n", encoding="utf-8")
    return str(f)


class TestParseo:
    def test_lee_las_cuatro_partes_de_una_linea(self):
        m = LOG_PATTERN.match(LINEAS[0])
        assert m is not None
        marca, ip, evento, mensaje = m.groups()
        assert marca == "2026-03-15 08:15:00"
        assert ip == "192.168.1.10"
        assert evento == "LOGIN_SUCCESS"
        assert mensaje == "User admin logged in"

    def test_una_linea_ilegible_se_cuenta_en_vez_de_desaparecer(self, tmp_path):
        """Un registro que el parser no entiende es un hallazgo, no un vacio."""
        f = tmp_path / "log.txt"
        f.write_text("\n".join(LINEAS + [
            "esto no tiene forma de linea de log",
            "2026-13-45 99:99:99 no.es.una.ip [X] y",
        ]) + "\n", encoding="utf-8")
        d = analyze(str(f))
        assert d["unparsed"] == 2
        assert d["parsed"] == len(LINEAS)

    def test_las_lineas_en_blanco_no_cuentan_como_ilegibles(self, tmp_path):
        f = tmp_path / "log.txt"
        f.write_text("\n\n".join(LINEAS) + "\n\n\n", encoding="utf-8")
        d = analyze(str(f))
        assert d["unparsed"] == 0
        assert d["parsed"] == len(LINEAS)

    def test_un_fichero_vacio_no_revienta(self, tmp_path):
        f = tmp_path / "vacio.txt"
        f.write_text("", encoding="utf-8")
        d = analyze(str(f))
        assert d["parsed"] == 0
        assert d["unique_ips"] == 0
        assert d["first"] is None and d["last"] is None


class TestRecuentos:
    def test_las_cifras_del_ejemplo(self, registro):
        d = analyze(registro)
        assert d["parsed"] == 6
        assert d["failed_logins"] == 2
        assert d["brute_force_attempts"] == 1
        assert d["unique_ips"] == 3

    def test_el_total_de_eventos_es_el_de_lineas_leidas(self, registro):
        d = analyze(registro)
        assert sum(d["event_counts"].values()) == d["parsed"]

    def test_los_fallidos_se_atribuyen_a_su_ip(self, registro):
        d = analyze(registro)
        assert d["top_failed_login_ips"][0] == ("10.0.0.5", 2)

    def test_el_reparto_por_dia_suma_el_total(self, registro):
        d = analyze(registro)
        assert sum(d["per_day"].values()) == d["parsed"]
        assert d["per_day"]["2026-03-15"] == 4
        assert d["per_day"]["2026-03-16"] == 2

    def test_el_reparto_por_hora_suma_el_total(self, registro):
        d = analyze(registro)
        assert sum(sum(c.values()) for c in d["per_hour"].values()) == d["parsed"]

    def test_la_primera_y_la_ultima_marca_acotan_el_periodo(self, registro):
        d = analyze(registro)
        assert d["first"] == "2026-03-15 08:15:00"
        assert d["last"] == "2026-03-16 09:00:00"
        assert d["first"] <= d["last"]

    def test_los_tops_no_pasan_de_cinco(self, tmp_path):
        lineas = [f"2026-03-15 08:{i:02d}:00 10.0.0.{i} [LOGIN_FAILED] x"
                  for i in range(1, 12)]
        f = tmp_path / "log.txt"
        f.write_text("\n".join(lineas), encoding="utf-8")
        d = analyze(str(f))
        assert len(d["top_ips"]) == 5
        assert len(d["top_failed_login_ips"]) == 5


class TestInforme:
    def test_el_informe_sale_de_las_cifras_y_no_al_reves(self, registro):
        """analyze() y build_report() son dos pasos: el informe no recuenta."""
        d = analyze(registro)
        assert build_report(d) == analyze_logs(registro)

    def test_las_cifras_aparecen_en_el_informe(self, registro):
        d = analyze(registro)
        informe = build_report(d)
        assert f"**Intentos de Login Fallidos:** {d['failed_logins']}" in informe
        assert f"**Intentos de Fuerza Bruta Detectados:** {d['brute_force_attempts']}" in informe
        for ip, conteo in d["top_ips"]:
            assert f"| {ip} | {conteo} |" in informe

    def test_un_registro_vacio_da_informe_sin_reventar(self, tmp_path):
        f = tmp_path / "vacio.txt"
        f.write_text("", encoding="utf-8")
        informe = build_report(analyze(str(f)))
        assert "Resumen de Eventos" in informe


class TestJson:
    def test_el_resumen_json_cuadra_con_el_analisis(self, registro, tmp_path):
        d = analyze(registro)
        salida = tmp_path / "web"
        nombres = export_json(d, str(salida))
        resumen = json.loads((salida / "resumen.json").read_text(encoding="utf-8"))
        assert resumen["lineas"] == d["parsed"] + d["unparsed"]
        assert resumen["analizadas"] == d["parsed"]
        assert resumen["ips"] == d["unique_ips"]
        assert resumen["fallidos"] == d["failed_logins"]
        assert set(nombres) == {"eventos.json", "top_ips.json", "top_fallidos.json",
                                "por_hora.json", "por_dia.json", "resumen.json"}

    def test_las_amenazas_son_solo_los_eventos_de_amenaza(self, registro, tmp_path):
        d = analyze(registro)
        salida = tmp_path / "web"
        export_json(d, str(salida))
        resumen = json.loads((salida / "resumen.json").read_text(encoding="utf-8"))
        assert resumen["amenazas"] == sum(d["event_counts"][e] for e in THREAT_EVENTS)
        # LOGIN_SUCCESS no es una amenaza y no debe colarse en la cuenta.
        assert resumen["amenazas"] < d["parsed"]

    def test_todos_los_ficheros_son_json_valido(self, registro, tmp_path):
        d = analyze(registro)
        salida = tmp_path / "web"
        for nombre in export_json(d, str(salida)):
            json.loads((salida / nombre).read_text(encoding="utf-8"))

    def test_cada_hora_declara_todos_los_tipos_de_evento(self, registro, tmp_path):
        """Si una hora omite un tipo, la grafica apilada queda con huecos."""
        d = analyze(registro)
        salida = tmp_path / "web"
        export_json(d, str(salida))
        filas = json.loads((salida / "por_hora.json").read_text(encoding="utf-8"))
        tipos = {e for e, _ in d["event_counts"].most_common()}
        for fila in filas:
            assert set(fila) - {"hora"} == tipos


class TestGeneradorDeLogs:
    def test_la_misma_semilla_da_el_mismo_registro(self):
        assert generate_entries(50, seed=7) == generate_entries(50, seed=7)

    def test_semillas_distintas_dan_registros_distintos(self):
        assert generate_entries(50, seed=1) != generate_entries(50, seed=2)

    def test_todo_lo_generado_lo_entiende_el_parser(self):
        """Si el generador y el parser se separan, el analisis mide cero."""
        for linea in generate_entries(300, seed=11):
            assert LOG_PATTERN.match(linea), f"el parser no entiende: {linea!r}"

    def test_las_entradas_salen_en_orden_cronologico(self):
        entradas = generate_entries(200, seed=5)
        marcas = [l[:19] for l in entradas]
        assert marcas == sorted(marcas)

    def test_se_generan_las_que_se_piden(self):
        assert len(generate_entries(123, seed=3)) == 123
