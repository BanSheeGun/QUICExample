bazel build //lib:all
bazel build //client:all
bazel build //server:all
bazel test //unit-test:all

mkdir bin
cp server/http_server.py bin/
cp server/https_server.py bin/
cp agent/agent.py bin/
cp bazel-bin/server/server bin/
cp bazel-bin/client/client bin/

openssl genrsa -des3 -out server.key 2048
openssl rsa -in server.key -out server.key
openssl req -new -x509 -key server.key -out ca.crt -days 3650
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey server.key -CAcreateserial -out server.crt
cat server.key server.crt > server.pem
mv server.crt bin/
mv server.key bin/
mv server.csr bin/
mv server.pem bin/
rm ca.*
