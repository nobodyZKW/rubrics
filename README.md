## SETUP 

### To build locally:

```bash
sudo apt-get install libjsoncpp-dev libssl-dev openssl     #install required dependency
g++ zodiacs_test.cpp -o tests zodiacs.cpp -ljsoncpp -lssl -lcrypto -lpthread
./tests
```

### To run in Docker:

```bash
docker build -t zodiacs .
docker run --rm zodiacs ./tests
```


### Endpoint Commands:

Note: the server generates self-signed `cert.pem`/`key.pem` if missing, so use `curl -k` to skip local certificate verification.

* Single Zodiac: ``` curl -G "https://localhost:8080/<chinese|western>?date=01-01-2000" ```
* Bulk Zodiac: 
```bash
curl -X POST https://localhost:8080/bulk \
-H "Content-Type: application/json" \
-d '["01-01-2000", "15-06-1995", "25-12-1988"]' 
```
* Zodiac Date Range: ``` curl "https://localhost:8080/range?start=01-01-2000&end=05-01-2000" ```
* Create Share ID: 
```bash
curl -X POST "https://localhost:8080/share" \
-H "Content-Type: application/json" \
-d '{"date": "01-01-2000"}'
```

* View Share ID: <pre> curl "https://localhost:8080/shared/<b>share id</b>" </pre>
* Logout: ``` curl -X POST "https://localhost:8080/logout" -H "Authorization: <session id>" ```
