BINARY_NAME=403bypasser

all: build

# Bağımlılıkları indir
deps:
	@echo "Checking dependencies..."
	go mod tidy
	@echo "Dependencies installed."

# Derle (bin klasörüne atar)
build: deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build -o bin/$(BINARY_NAME) main.go
	@echo "Build complete: ./bin/$(BINARY_NAME)"

# SİSTEME KUR (Bunu ekledik)
# Derlenen dosyayı /usr/local/bin içine taşır. Sudo şifresi isteyebilir.
install: build
	@echo "Installing to system..."
	sudo mv bin/$(BINARY_NAME) /usr/local/bin/
	@echo "SUCCESS! You can now run '$(BINARY_NAME)' from anywhere!"

# Temizlik
clean:
	@echo "Cleaning..."
	rm -rf bin
	rm -f results.txt