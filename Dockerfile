FROM gitpod/workspace-full:latest

USER root
# Install custom tools, runtime, etc.
RUN apt-get update && apt-get upgrade -y && apt-get install -y libcap2 libcap-ng0 \
    && apt-get clean && rm -rf /var/cache/apt/* && rm -rf /var/lib/apt/lists/* && rm -rf /tmp/*

#Obtain libcap-dev package
RUN wget http://ge.archive.ubuntu.com/ubuntu/pool/main/libc/libcap2/libcap-dev_2.25-1.2_amd64.deb -O ./libcap-dev_2.25-1.2_amd64.deb || true

#Install libcap-dev

RUN apt install ./libcap-dev_2.25-1.2_amd64.deb

USER gitpod
# Apply user-specific settings
#ENV ...

# Give back control
USER root
