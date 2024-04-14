How to run main application:
1. Put an .env file into the same directory as the rest of the files
2. The .env file should have a variable named NOT_MY_KEY set to your AES KEY. ex. NOT_MY_KEY="nNOGB0kqYfz0qelm4vdfYDUYUGt59rA2cO1Lpuw+mgU="
4. Open terminal
5. Locate where project2.py is
6. Run "python project2.py"

test.py is used as the testsuite
How to run test suite:
1. Have project2.py run
2. Open a separate terminal
3. Locate where test.py is 
4. Run "python test.py"

Purpose:
Grants jwks keys with an expiration date upon request

RESTful Commands:
- GET:/.well-known/jwks.json"
Reads all valid private keys from the database and creates a JWKS response from those private keys

- POST:/register 
Accepts user registration details in request body using this JSON format:
{"username": "$MyCoolUsername", "email": "$MyCoolEmail"}

- POST:/auth
Stores an unexpired, signed JWT on a POST request into database and logs user and gives them a jwks key

Unacceptable commands:
- PATCH
- PUT
- DELETE
- HEAD
  
Private keys are encrypted using symmetric AES encryption
Passwords are generated using UUIDv4


