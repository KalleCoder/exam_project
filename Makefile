SPEED = 115200
PORT = /dev/ttyUSB0

# Define the target for the client application
client:
	python3 ./client/main.py $(PORT) $(SPEED)

test:
	python3 ./client/comm.py $(PORT) $(SPEED)

server:
	@cd Server; \
	export PLATFORMIO_BUILD_FLAGS ="-DSPEED=$(SPEED)"; \
	pio run -t upload

clean:
	@rm -rf Server/.pio Server/.vscode client/__pycache__

# Declare that 'client' is a phony target
.PHONY: client server clean