SCRIPT = peid_to_yara.py

all: clean python3

python3:
	python3 $(SCRIPT) -o test.txt ./userdb/userdb*

clean:
	rm -f test.txt
