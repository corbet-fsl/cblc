"""Test-only independent inspection/fault injection of the libSQL database file."""
import json
import sqlite3
import sys

request = json.load(sys.stdin)
with sqlite3.connect(request['path'], timeout=5) as connection:
    connection.create_function('bytes', 1, lambda value: bytes(json.loads(value)))
    connection.executescript('''
      CREATE TEMP VIEW frontiers AS SELECT
      bytes(json_extract(CAST(value AS TEXT),'$.state')) AS state,
      bytes(json_extract(CAST(value AS TEXT),'$.latest_request')) AS latest_request,
      json_extract(CAST(value AS TEXT),'$.version') AS version, substr(key,10,32) AS owner
      FROM cssr_records WHERE community_id='community.example' AND substr(key,1,1)=x'01';
      CREATE TEMP VIEW latest_acceptances AS SELECT value FROM cssr_records WHERE community_id='community.example' AND substr(key,1,1)=x'02';
      CREATE TEMP VIEW markers AS SELECT substr(key,50,32) AS marker FROM cssr_records WHERE community_id='community.example' AND substr(key,1,1)=x'04';
      CREATE TEMP VIEW configuration AS SELECT CAST(value AS INTEGER) AS clock_floor FROM cssr_records WHERE community_id='community.example' AND key=x'636c6f636b';
    ''')
    if request['execute']:
        connection.executescript(request['sql'])
        rows = []
    else:
        rows = connection.execute(request['sql'], [bytes(p) for p in request['params']]).fetchall()
    json.dump(rows, sys.stdout, default=list)
