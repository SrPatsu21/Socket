# BUILD

```shell
mkdir build
cd build
cmake ..
cmake --build .
./udp_server 8080 -v --buffsize 1024 --neterr 25 --heartbeat 1 --heartms 3000
```

- if Release

```shell
cmake .. -DCMAKE_BUILD_TYPE=Release
```
