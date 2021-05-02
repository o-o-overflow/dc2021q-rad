from rust:alpine as build
workdir /src
copy . /src/
run apk update && apk add alpine-sdk openssl-dev git
run cargo build --release && cargo build --tests --release

from rust:alpine as proxy
workdir /
run apk update && apk add docker
copy --from=build /src/target/*/rad_proxy /
copy data/proxy.toml data/node.toml /
entrypoint ["/rad_proxy"]

from rust:alpine as service
workdir /
copy --from=0 /src/target/*/rad_exec /src/target/*/rad_fw /
copy data/de438s.exb data/de438s.fxb /data/
run echo 'OOO{tho.gh_t.is.be_m.dness_ye..t.er...s_m.th.d..n.it?}' >/flag && chmod 440 /flag
entrypoint ["/rad_exec"]
