# JSON web service

## Build

```
mkdir build
cd build
cmake ..
make
```


### Build in docker

Install docker

#### Pull image

```
docker images
docker pull dokken/ubuntu-18.04
docker images
docker tag <ID> lora
```

#### Build

Install tools & dependencies

```
apt install cmake autoconf libtool build-essential gcc g++ unzip cmake git curl wget clang libmicrohttpd-dev
```

Build

```
docker run -itv /home/andrei/src:/home/andrei/src lora bash

cd /home/andrei/src/ws-lora
mkdir -p build
cd /home/andrei/src/ws-lora/build
rm *;rm -r CMakeFiles/
cmake ..
make
./lora-ws -?
```

#### Commit

```
docker ps -a
docker commit stoic_ramanujan
docker images
docker tag c30cb68a6443 lora
# Remove closed containers
docker rm $(docker ps -qa --no-trunc --filter "status=exited")
```

## Deploy

Stop service first

```
pkill lora-ws
```

Strip and deploy

```
cd /home/andrei/src/ws-lora/build
sudo chown andrei:andrei lora-ws
strip lora-ws
scp lora-ws andrei@lora.commandus.com:~/lora/
```

Run service

```
cd lora
./lora-ws -d
```

### Build & deploy web app:

```
cd ~/src/angular/website-lora/
ng build
cd ~/src/angular/website-lora/dist/website-lora/browser/
scp -r * andrei@lora.commandus.com:/var/www/html/lora
```

### Run

Login into server:

```
ssh andrei@lora.commandus.com
```

Before first run install dependencies:

```
cd ~/lora
sudo apt install libmicrohttpd12/bionic
```

Run

```
ssh andrei@lora.commandus.com
cd ~/lora
./ws-lora -d
```


## Examples

- keygen generate keys by the "master" key
- netid
- gw parse gateway packet (in hex)
- rfm parse FRM packet (in hex)

```
wget -q -S -O - --post-data '["netid", "78ff"]' http://localhost:8050/
{"addr": "78ff0000", "netid": "3c", "type": "0", "id": "3c", "nwkId": "3c", "addrMin": "78000000", "addrMax": "79ffffff"}
```

```
wget -q -S -O - --post-data '["keygen", "1a2b3c", "masterkey"]' http://localhost:8050/
{"addr": "1a2b3c00", "eui": "68296f882dfd07e0", "nwkKey": "bd18f525a35b23aa7b6016c439f89989", 
"appKey": "ce5dfc2a4d5b17478b4b6aef35866feb"}andrei@office221:~/src/ws-lora$ 
```

```
wget -q -S -O - --post-data '["rfm", "4030034501807b000239058672800d394af6863bf99148f63bec91543c086c171be37f3953"]' http://localhost:8050/
{"mhdr": {"mtype": "unconfirmed-data-up", "major": 0, "rfu": 0}, "addr": "30034501", 
"fctrl": {"foptslen": 0, "classB": false, "addrackreq": false, "ack": false, "adr": true},
"fcnt": 31488, "fport": 2, "payload": "39058672800d394af6863bf99148f63bec91543c086c171be37f3953"} 
``` 

```
wget -q -S -O - --post-data '["rfm", "4030034501807b000239058672800d394af6863bf99148f63bec91543c086c171be37f3953"]' https://lora.commandus.com/json/clause
```

```
wget -q -S -O - --post-data '["gw", "02bbe50000006cc3743eed467b227278706b223a5b7b22746d7374223a343032333131313534302c226368616e223a332c2272666368223a302c2266726571223a3836342e3730303030302c2273746174223a312c226d6f6475223a224c4f5241222c2264617472223a22534631324257313235222c22636f6472223a22342f35222c226c736e72223a2d31382e352c2272737369223a2d3132312c2273697a65223a33372c2264617461223a22514441445251474151774143334749312b374553394d697030356a436c6f536f464e367a634b65437877394d7357457634513d3d227d5d7d"]' https://lora.commandus.com/json/clause
```
