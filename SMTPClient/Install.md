# BUILD

```shell
sudo apt install libssl-dev
mkdir build
cd build
cmake ..
cmake --build .
./smtp_client 25 localhost sender@example.com recipient@example.com "Hi" "Test message" -v
```

- if Release

```shell
cmake .. -DCMAKE_BUILD_TYPE=Release
```

- Init SMTP server

```shell
python3 -m aiosmtpd -n -l localhost:25
```
