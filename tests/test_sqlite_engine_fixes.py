"""H-03..H-06: the src/sqlite engine on real SQLite files built with the standard library."""
import sqlite3

import pytest

from src.sqlite.engine import ForensicSQLiteEngine, parse_create_table_sql


def _engine(path):
    diagnostics, records = ForensicSQLiteEngine().process_database(path)
    return diagnostics, records


# ---------------------------------------------------------------- H-03
def test_h03_many_tables_schema_spanning_pages_still_reads_rows(tmp_path):
    db = tmp_path / "many.db"
    c = sqlite3.connect(db)
    for i in range(120):
        c.execute(f"CREATE TABLE t{i:03d} (a INTEGER, b TEXT)")
    c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    c.executemany("INSERT INTO messages(body) VALUES (?)", [(f"message number {i}",) for i in range(20)])
    c.commit()
    page1_type = open(db, "rb").read(200)[100]
    c.close()
    assert page1_type == 0x05, "fixture must make page 1 an interior page, otherwise it proves nothing"

    _, records = _engine(db)
    msgs = [r for r in records if r.table_name == "messages" and r.source_origin_zone == "ACTIVE_BTREE"]
    assert len(msgs) == 20
    assert sorted(r.columns_dict["body"] for r in msgs) == sorted(f"message number {i}" for i in range(20))


# ---------------------------------------------------------------- H-06
def test_h06_bigint_primary_key_keeps_its_stored_value(tmp_path):
    db = tmp_path / "pk.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE tx (txn_id BIGINT PRIMARY KEY, amount REAL)")
    c.execute("INSERT INTO tx VALUES (987654321012, 10.5)")
    c.commit()
    c.close()
    _, records = _engine(db)
    rec = [r for r in records if r.table_name == "tx"][0]
    assert rec.columns_dict["txn_id"] == 987654321012            # not the rowid (1)


def test_h06_table_constraint_primary_key_is_a_rowid_alias(tmp_path):
    db = tmp_path / "pk2.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t (id INTEGER, name TEXT, PRIMARY KEY (id))")
    c.execute("INSERT INTO t(id, name) VALUES (41, 'x')")
    c.commit()
    c.close()
    _, records = _engine(db)
    rec = [r for r in records if r.table_name == "t"][0]
    assert rec.columns_dict["id"] == 41                           # the id is not lost as None


def test_h06_declared_type_must_be_exactly_integer():
    _, _, _, ipk = parse_create_table_sql("CREATE TABLE a (id INTEGER PRIMARY KEY, v TEXT)")
    assert ipk == "id"
    for ddl in (
        "CREATE TABLE a (id INT PRIMARY KEY, v TEXT)",
        "CREATE TABLE a (id BIGINT PRIMARY KEY, v TEXT)",
        "CREATE TABLE a (id INTEGER PRIMARY KEY DESC, v TEXT)",
        "CREATE TABLE a (id INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID",
        "CREATE TABLE a (id INTEGER, k INTEGER, PRIMARY KEY (id, k))",
    ):
        assert parse_create_table_sql(ddl)[3] is None, ddl


# ---------------------------------------------------------------- H-04 / H-05
def _deleted_rows_db(path, n=600):
    c = sqlite3.connect(path)
    c.execute("PRAGMA secure_delete=OFF")
    c.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, note TEXT)")
    c.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, payee TEXT, amount REAL, status TEXT)")
    c.executemany("INSERT INTO payments(payee, amount, status) VALUES (?,?,?)",
                  [(f"payee{i:04d}@ybl", 100.0 + i, "SUCCESS") for i in range(n)])
    c.commit()
    c.execute("DELETE FROM payments")
    c.commit()
    c.close()


def _residual(records):
    return [r for r in records if r.source_origin_zone != "ACTIVE_BTREE"]


def test_h04_adjacent_deleted_cells_are_all_recovered(tmp_path):
    db = tmp_path / "del.db"
    _deleted_rows_db(db)
    _, records = _engine(db)
    rowids = {r.sqlite_rowid for r in _residual(records) if r.table_name.endswith("payments")}
    assert len(rowids) >= 570, f"only {len(rowids)} of 600 deleted rows recovered"      # was 301, every second row
    odd = [x for x in rowids if x % 2 == 1]
    assert len(odd) >= 280 and len(rowids) - len(odd) >= 280


def test_h05_deleted_rows_are_not_attributed_to_the_wrong_table(tmp_path):
    db = tmp_path / "del2.db"
    _deleted_rows_db(db)
    _, records = _engine(db)
    wrong = [r for r in _residual(records) if r.table_name == "contacts"]
    assert wrong == [], f"{len(wrong)} deleted payments rows were reported as contacts"


def test_h05_ambiguous_record_is_labelled_not_guessed(tmp_path):
    db = tmp_path / "amb.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE a (id INTEGER PRIMARY KEY, x TEXT, y TEXT)")
    c.execute("CREATE TABLE b (id INTEGER PRIMARY KEY, x TEXT, y TEXT)")
    c.executemany("INSERT INTO a(x, y) VALUES (?,?)", [(f"alpha text {i:04d}", f"beta text {i:04d}") for i in range(300)])
    c.commit()
    c.execute("DELETE FROM a")
    c.commit()
    c.close()
    _, records = _engine(db)
    names = {r.table_name for r in _residual(records)}
    # Either the page owner is known and it is `a`, or the engine says it cannot tell: never `b` alone.
    assert "b" not in names
    assert names <= {"a", "AMBIGUOUS: a | b"}


def test_h05_row_written_before_alter_table_is_not_shifted(tmp_path):
    db = tmp_path / "alter.db"
    c = sqlite3.connect(db)
    c.execute("PRAGMA secure_delete=OFF")
    c.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    c.executemany("INSERT INTO notes(title, body) VALUES (?,?)", [(f"title {i:04d}", f"body text {i:04d}") for i in range(200)])
    c.commit()
    c.execute("ALTER TABLE notes ADD COLUMN tag TEXT")
    c.commit()
    c.execute("DELETE FROM notes")
    c.commit()
    c.close()
    _, records = _engine(db)
    rec = [r for r in _residual(records) if r.table_name == "notes"]
    assert rec
    for r in rec:
        assert str(r.columns_dict.get("title", "")).startswith("title "), r.columns_dict       # title stays title
        assert str(r.columns_dict.get("body", "")).startswith("body text "), r.columns_dict
