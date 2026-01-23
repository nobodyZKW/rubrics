# Use a base image with C++ compiler
FROM gcc:11

# Set working directory
WORKDIR /app

# Copy source files
COPY zodiacs.cpp .
COPY zodiacs.h .
COPY httplib.h .
COPY zodiacs_test.cpp .

# Create static directory and copy HTML
RUN mkdir static
RUN mkdir test
COPY static/index.html static/
COPY test/catch.hpp test/

# Install development dependencies
RUN apt-get update && apt-get install -y libjsoncpp-dev libssl-dev openssl

# Expose port 8080
EXPOSE 8080

# Provide shell access for development
CMD ["/bin/bash"] 
