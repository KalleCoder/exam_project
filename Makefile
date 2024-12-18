# Declare that 'client' is a phony target
.PHONY: client

# Define the target for the client application
client:
	python3 ./client/main.py COM3 9600

