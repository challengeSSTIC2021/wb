FROM ubuntu:20.04

ENV USER=docker-user
ENV HOME=/home/$USER
ENV OUT_DIR=$HOME/out

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        clang \
        llvm-dev \
        lld \
        ninja-build \
        python3 \
        python3-cffi \
        python3-dev \
        python3-pip && \
    apt-get clean && \
    update-alternatives --set cc /usr/bin/clang && \
    update-alternatives --set c++ /usr/bin/clang++ && \
    python3 -m pip install python_camellia pycryptodome && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' $USER

WORKDIR $HOME

ADD . $HOME/whitebox

RUN mkdir $OUT_DIR && \
    chown -R $USER:$USER $HOME && \
    chmod -R a-w $HOME/whitebox

USER $USER

ENTRYPOINT ["python3", "./whitebox/docker_script/runner.py"]
