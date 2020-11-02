#!/usr/bin/env bash

mkdir -p com_github_jetstack_cert_manager/hack
curl https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-1.19.2-$(uname -s | tr '[:upper:]' '[:lower:]')-amd64.tar.gz |
    tar xz --strip-components=1 -C com_github_jetstack_cert_manager/hack
