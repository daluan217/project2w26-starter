# CS 118 Project 2: Testing Guide

There are a lot of details here. All you **need** to know is how it should work (to help you debug your work) and how to use `./helper`.

## How it should work

The server is run with a port number, for example, `55001`.
Then the client is run with the hostname and port of the server. In this case, it would be `localhost` and `55001`, respectively.

At this point, the client and server should do a handshake and then wait for input.
Entering strings into one should result in the same string being printed in the other, which is how the autograder tests whether your encryption is working.

## Using the Autograder

The `./helper` script manages a Docker container that is the same as the grading environment in Gradescope.
### Basic Commands
* **Run All Tests**:

    ```bash
    ./helper run
    ```
    This downloads the container, compiles your code, and runs the full test suite.
* **Clean up the docker container**:  Sometimes things go wrong and you'll want to reset the docker container:

  ```bash
  ./helper clean
  ``` 
* **Run Specific Tests**:
    To save time, you can run individual test cases:
    ```bash
    ./helper test test_client_hello          # Check if your Client Hello is valid
    ./helper test test_server_hello          # Check if your Server Hello is valid
    ./helper test test_encrypt_and_mac_client # Check client data encryption
    ./helper test test_encrypt_and_mac_server # Check server data encryption
    ```

---

## 2. Interactive & Manual Debugging

The most effective way to debug is to enter the container and run your binaries manually. This allows you to use `gdb`, `valgrind`, or `printf` debugging in real-time.

### Step 1: Enter the Container
```bash
./helper interactive
````

You are now inside the Linux environment (`/autograder`).

### Step 2: Compile Your Code

```bash
cd /autograder/submission
make
```

### Step 3: The "Keys" Directory 

Your code loads files like `server_key.bin` and `server_cert.bin` using relative paths (e.g., `fopen("server_key.bin")`). Therefore, you must run your executables from the directory where these keys exist.

The autograder stores keys in `/autograder/source/keys`.

1. **Navigate to the keys directory:**
    ```bash
    cd /autograder/source/keys
    ```
    
1. **Generate fresh keys/certificates:**
    ```bash
    ./gen_files
    ```

### Step 4: Run Your Code

From inside `/autograder/source/keys`, run your compiled binaries using relative paths:

- **Start Server:**
    
    ```bash
    ../../submission/server 8080
    ```
    
- **Start Client:**
    
    ```bash
    ../../submission/client localhost 8080
    ```

---

## 3. Testing Against the Reference Solution

We provide a reference implementation (binary only) inside the container. This is useful for isolating bugs (e.g., "Is my Client broken, or is my Server broken?").

The reference binaries are located at:

- `/autograder/source/src/server`
- `/autograder/source/src/client`
    

### Example: Test Your Client vs. Reference Server

1. Go to the keys directory:
    
    ```bash
    cd /autograder/source/keys
    ```
    
2. Start the reference server:
    
    ```bash
    ../src/server 8080
    ```
    
3. Start your client:
    
    ```bash
    ../../submission/client localhost 8080
    ```
    

### Example: Test Your Server vs. Reference Client

1. Start your server:
    
    ```bash
    ../../submission/server 8080
    ```
    
2. Start the reference client:
    
    ```bash
    ../src/client localhost 8080
    ```

---

## 4. Testing Error Cases (Custom Test Cases)

The `gen_files` script generates several "bad" files you can use to verify your error handling. These are how the autograder makes sure your code crashes on bad input.

Inside the container, these are located at `/autograder/source/keys`. After doing the copies listed below, run the client and server to check their behavior.

### 1. Test "Bad DNS Name" (Exit Code 2)

    ```bash
    cp server_cert2.bin server_cert.bin
    ```
    

### 2. Test "Expired Certificate" (Exit Code 1)

    ```bash
    cp server_cert_expired.bin server_cert.bin
    ```
    

### 3. Test "Bad Signature" (Exit Code 1)

Test if your client validates the CA signature on the certificate.

    ```bash
    cp ca_public_key2.bin ca_public_key.bin
    ```

---

## 5. Local Testing (Host Machine)

You can run locally without Docker if you have OpenSSL installed (`apt install libssl-dev` or `brew install openssl`).

1. Compile: `cd project && make`
    
2. Generate Keys:
    ```bash
    cd keys
    ./gen_files
    ```
    
3. Run from the `keys` directory:
    
    ```bash
    ../project/server 8080
    ```
