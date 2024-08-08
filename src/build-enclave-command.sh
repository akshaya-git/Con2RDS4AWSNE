nitro-cli terminate-enclave --all
docker rmi vsock-sample-server:latest
rm vsock_sample_server.eif
docker build -t vsock-sample-server -f Dockerfile.server .
nitro-cli build-enclave --docker-uri vsock-sample-server --output-file vsock_sample_server.eif
nitro-cli run-enclave --eif-path vsock_sample_server.eif --cpu-count 2 --memory 6000
nitro-cli describe-enclaves
