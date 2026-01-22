## SETUP 

### To build locally:

```bash
sudo apt-get install libjsoncpp-dev     #install required dependency
g++ zodiacs_test.cpp -o tests zodiacs.cpp -ljsoncpp -lcrypto -lpthread
./tests
```

### To run in Docker:

```bash
docker build -t zodiacs .
docker run --rm zodiacs ./tests
```


### Endpoint Commands:

* Single Zodiac: ``` curl -G "http://localhost:8080/<chinese|western>?date=01-01-2000" ```
* Bulk Zodiac: 
```bash
curl -X POST http://localhost:8080/bulk \
-H "Content-Type: application/json" \
-d '["01-01-2000", "15-06-1995", "25-12-1988"]' 
```
* Zodiac Date Range: ``` curl "http://localhost:8080/range?start=01-01-2000&end=05-01-2000" ```
* Create Share ID: 
```bash
curl -X POST "http://localhost:8080/share" \
-H "Content-Type: application/json" \
-d '{"date": "01-01-2000"}'
```

* View Share ID: <pre> curl "http://localhost:8080/shared/<b>share id</b>" </pre>
