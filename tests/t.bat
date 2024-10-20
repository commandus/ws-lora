wget http://127.0.0.1:8050/json/clause -H 'Content-Type:application/json' -O- --post-file classes.json 2>2.txt
wget http://127.0.0.1:8050/json/clause -H 'Content-Type:application/json' -O- --post-file keygen.json 2>2.txt
wget http://127.0.0.1:8050/json/clause -H 'Content-Type:application/json' -O- --post-file netid.json 2>2.txt
wget http://127.0.0.1:8050/json/clause -H 'Content-Type:application/json' -O- --post-file urn.json 2>2.txt
wget http://127.0.0.1:8050/version -H 'Content-Type:application/json' -O- --post-data '' 2>2.txt
wget http://127.0.0.1:8050/clause -H 'Content-Type:application/json' -O- --post-data '{}' 2>2.txt