# Artifact of of High-threshold Asynchronous Distributed Key Generation


## File structures


## Running on local machine

### Required tools
1. Install `Docker`_. (For Linux, see `Manage Docker as a non-root user`_) to
run ``docker`` without ``sudo``.)

2. Install `docker-compose`

### Building

1. The image will need to be built  (this will likely take a while). Inside the `htadkg` folder run
```
$ docker-compose build adkg
```

### Running tests

1. You need to start a shell session in a container. The first run will take longer if the docker image hasn't already been built:
```
$ docker-compose run --rm adkg bash
```

2. Then, to test the `adkg` code locally, i.e., multiple thread in a single docker container, you need to run the following command with parameters:
      - `num`: Number of nodes, 
      - `ths`: fault-tolerance threshold, and 
      - `deg`: Degree of the ADKG polynomial. 

   Note that `n>3*t` and `deg < n-t`
```
$ pytest tests/test_adkg.py -o log_cli=true --num 4 --ths 1 --deg 2
```
 
## Running locally on multiple processes within a docker image

Note: Required tools and build instructions are same as above

### Running tests
1. Start a docker image by running
```$docker-compose run --rm adkg bash ```

2. Start the ADKG instances
```$sh scripts/launch-tmuxlocal.sh apps/tutorial/adkg-tutorial.py [NUM_NODES]```


## Running in AWS instances
Please refer to `aws/README.md` for detailed information on how to run the protocol using amazon web services
