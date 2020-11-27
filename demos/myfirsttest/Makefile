build: install move

install:
	cd ../../core && mvn clean install -DskipTests
	cd ../../suite/spdz && mvn clean install -DskipTests
	cd ../common && mvn clean install -DskipTests
	mvn clean install -DskipTests

move:
	mkdir -p server1;
	mkdir -p server2;
	mkdir -p server3;
	cp target/fresco-test-demo.jar server1;
	cp target/fresco-test-demo.jar server2;
	cp target/fresco-test-demo.jar server3;

runSpdz:
	cd server1 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 1 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s spdz -Dspdz.preprocessingStrategy=MASCOT -x 100 > log.txt 2>&1 &
	cd server2 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 2 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s spdz -Dspdz.preprocessingStrategy=MASCOT -x 30 > log.txt 2>&1 &
	cd server3 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 3 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s spdz -Dspdz.preprocessingStrategy=MASCOT -x 20 2>&1 | tee log.txt

runDummy:
	cd server1 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 1 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s dummyArithmetic -x 100 > log.txt 2>&1 &
	cd server2 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 2 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s dummyArithmetic -x 30 > log.txt 2>&1 &
	cd server3 && java -jar fresco-test-demo.jar -l -e SEQUENTIAL_BATCHED -i 3 -p 1:localhost:8081 -p 2:localhost:8082 -p 3:localhost:8083 -s dummyArithmetic -x 20 2>&1 | tee log.txt

clean:
	rm -rf server1 server2 server3
