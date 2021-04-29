from rust:alpine
workdir /src
copy . /src/
run apk update && apk add alpine-sdk
run cargo build --release

from rust:alpine
workdir /
copy --from=0 /src/target/*/rad_exec /src/target/*/rad_fw /
copy data/de438s.exb data/de438s.fxb /data/
entrypoint ["/rad_exec"]
