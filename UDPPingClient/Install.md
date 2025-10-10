# BUILD

```shell
mkdir build
cd build
cmake ..
cmake --build .
./udp_client.out 8080 127.0.0.1 -v --buffsize 1024 --ping 1 --pingtimes 10 --timeout 1000 --heartbeat 1 --heartms 1000
```

- if Release

```shell
cmake .. -DCMAKE_BUILD_TYPE=Release
```
